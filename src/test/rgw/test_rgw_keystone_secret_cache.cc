// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

/*
 * Unit tests for rgw::auth::keystone::SecretCache: the per-process cache of
 * Keystone-validated S3 credentials and the request-path policy on top of
 * it. Keystone itself is replaced by a scripted FakeFetcher, the clock by a
 * settable fake, so every scenario is deterministic and runs in both the
 * synchronous (null_yield, OS threads) and the asio (io_context coroutine)
 * variant that the beast frontend uses.
 */

#include "rgw_auth_keystone.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <latch>
#include <limits>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <boost/asio/spawn.hpp>
#include <gtest/gtest.h>

#include "common/async/yield_waiter.h"
#include "common/ceph_argparse.h"
#include "common/common_init.h"
#include "global/global_context.h"
#include "global/global_init.h"
#include "rgw_perf_counters.h"

using rgw::auth::keystone::FetchResult;
using rgw::auth::keystone::SecretCache;
using rgw::auth::keystone::SignedSample;
using rgw::keystone::TokenEnvelope;

namespace {

/* ---- fake clock ------------------------------------------------------ */

std::atomic<time_t> fake_now_secs{1'000'000};

utime_t fake_clock()
{
  return utime_t(fake_now_secs.load(), 0);
}

void advance_clock(time_t secs)
{
  fake_now_secs += secs;
}

/* ---- test data --------------------------------------------------------- */

constexpr time_t far_future = std::numeric_limits<time_t>::max() / 2;

TokenEnvelope make_token(const std::string& user_id = "user-1",
                         time_t expires = far_future)
{
  TokenEnvelope t;
  t.user.id = user_id;
  t.user.name = "name-" + user_id;
  t.project.id = "project-1";
  t.project.name = "project";
  t.set_expires(expires);
  return t;
}

SignedSample make_sample(const std::string& akid = "AKID",
                         const std::string& signature = "good")
{
  return SignedSample{akid, "string-to-sign", signature};
}

FetchResult ok_result(const std::string& secret = "s3cr3t",
                      const TokenEnvelope& token = make_token())
{
  FetchResult r;
  r.token = token;
  r.secret = secret;
  return r;
}

FetchResult failed_result(int failure_reason)
{
  FetchResult r;
  r.failure_reason = failure_reason;
  return r;
}

FetchResult token_without_secret(int failure_reason,
                                 const TokenEnvelope& token = make_token())
{
  FetchResult r;
  r.token = token;
  r.failure_reason = failure_reason;
  return r;
}

/* ---- fake Keystone ------------------------------------------------------ */

/* Copyable functor (SecretCache::fetch_fn copies it); all state is shared.
 * The gate holds every fetch that arrives while it is closed: a coroutine
 * suspends on its own yield_waiter, a thread blocks on the condition
 * variable. open() releases all of them. */
class FakeFetcher {
  struct State {
    std::atomic<int> calls{0};
    std::atomic<int> concurrent{0};
    std::atomic<int> max_concurrent{0};
    std::function<FetchResult(int call_no, const SignedSample&)> script;

    std::mutex mutex;
    bool gate_open = true;
    std::condition_variable cond;
    std::list<std::unique_ptr<ceph::async::yield_waiter<void>>> waiters;
    std::vector<long> timeouts;
  };
  std::shared_ptr<State> st = std::make_shared<State>();

 public:
  FakeFetcher()
  {
    st->script = [] (int, const SignedSample&) { return ok_result(); };
  }

  void set_script(std::function<FetchResult(int, const SignedSample&)> s)
  {
    st->script = std::move(s);
  }
  void close_gate()
  {
    std::lock_guard l{st->mutex};
    st->gate_open = false;
  }
  void open_gate()
  {
    std::list<std::unique_ptr<ceph::async::yield_waiter<void>>> waiters;
    {
      std::lock_guard l{st->mutex};
      st->gate_open = true;
      waiters.swap(st->waiters);
    }
    st->cond.notify_all();
    for (auto& w : waiters) {
      w->complete(boost::system::error_code{});
    }
  }
  int calls() const { return st->calls.load(); }
  int max_concurrent() const { return st->max_concurrent.load(); }
  std::vector<long> timeouts() const
  {
    std::lock_guard l{st->mutex};
    return st->timeouts;
  }
  /* number of fetches currently parked at the closed gate */
  size_t parked() const
  {
    std::lock_guard l{st->mutex};
    return st->waiters.size();
  }

  FetchResult operator()(const DoutPrefixProvider*, const SignedSample& sample,
                         optional_yield y, long timeout_secs) const
  {
    const int call_no = ++st->calls;
    const int now = ++st->concurrent;
    int seen = st->max_concurrent.load();
    while (now > seen && !st->max_concurrent.compare_exchange_weak(seen, now)) {
    }
    {
      std::lock_guard l{st->mutex};
      st->timeouts.push_back(timeout_secs);
    }
    wait_at_gate(y);
    --st->concurrent;
    return st->script(call_no, sample);
  }

 private:
  void wait_at_gate(optional_yield y) const
  {
    std::unique_lock l{st->mutex};
    if (st->gate_open) {
      return;
    }
    if (y) {
      auto& waiter = *st->waiters.emplace_back(
          std::make_unique<ceph::async::yield_waiter<void>>());
      /* releases the lock right before the coroutine suspends */
      waiter.async_wait(l, y.get_yield_context());
    } else {
      st->cond.wait(l, [this] { return st->gate_open; });
    }
  }
};

/* ---- one request against the cache -------------------------------------- */

struct Outcome {
  std::optional<SecretCache::access_result> result;
  std::optional<int> thrown_int;
  std::exception_ptr eptr;

  bool granted(const std::string& secret) const
  {
    return result && result->token && result->secret_key &&
        *result->secret_key == secret && result->failure_reason == 0;
  }
  bool denied(int reason) const
  {
    return result && !result->token && !result->secret_key &&
        result->failure_reason == reason;
  }
};

struct Request {
  SignedSample sample = make_sample();
  std::string expected_secret = "s3cr3t";  // what the "signature" verifies against
  bool ignore_signature = false;
};

class SecretCacheTest : public ::testing::Test {
 protected:
  CephContext* cct = g_ceph_context;
  const NoDoutPrefix dpp{cct, ceph_subsys_rgw};
  std::unique_ptr<SecretCache> cache;

  void SetUp() override
  {
    fake_now_secs = 1'000'000;
    perfcounter->reset();
    set_conf("rgw_keystone_token_cache_size", "10000");
    set_conf("rgw_keystone_token_cache_ttl", "300");
    reset_cache();
  }

  static uint64_t counter(int idx)
  {
    return perfcounter->get(idx);
  }

  void set_conf(const char* name, const char* value)
  {
    ASSERT_EQ(0, cct->_conf.set_val(name, value));
  }

  /* the cache snapshots size and ttl in its constructor */
  void reset_cache()
  {
    cache = std::make_unique<SecretCache>(cct);
    cache->set_clock_for_testing(fake_clock);
  }

  Outcome call(const Request& req, const FakeFetcher& fetcher, optional_yield y)
  {
    Outcome o;
    try {
      o.result = cache->get_or_fetch(
          &dpp, req.sample,
          [&] (const std::string& secret) { return secret == req.expected_secret; },
          req.ignore_signature, fetcher, y);
    } catch (const int err) {
      o.thrown_int = err;
    } catch (...) {
      o.eptr = std::current_exception();
    }
    return o;
  }

  /* N requests on N OS threads, null_yield */
  std::vector<Outcome> run_threads(const std::vector<Request>& reqs,
                                   const FakeFetcher& fetcher,
                                   const std::function<void()>& while_running = {})
  {
    std::vector<Outcome> outcomes(reqs.size());
    {
      std::vector<std::jthread> threads;
      for (size_t i = 0; i < reqs.size(); ++i) {
        threads.emplace_back([&, i] {
          outcomes[i] = call(reqs[i], fetcher, null_yield);
        });
      }
      if (while_running) {
        while_running();
      }
    }
    return outcomes;
  }

  /* N requests as coroutines on one io_context, driven single-threaded
   * (deterministic). while_parked() runs after poll() with everything
   * suspended, typically to open the fetcher's gate. */
  std::vector<Outcome> run_coroutines(const std::vector<Request>& reqs,
                                      const FakeFetcher& fetcher,
                                      const std::function<void()>& while_parked = {})
  {
    boost::asio::io_context ctx;
    std::vector<Outcome> outcomes(reqs.size());
    for (size_t i = 0; i < reqs.size(); ++i) {
      boost::asio::spawn(ctx, [&, i] (boost::asio::yield_context yield) {
            outcomes[i] = call(reqs[i], fetcher, optional_yield{yield});
          }, [] (std::exception_ptr eptr) {
            if (eptr) std::rethrow_exception(eptr);
          });
    }
    ctx.poll();
    if (while_parked) {
      while_parked();
      ctx.restart();
      ctx.run();
    }
    EXPECT_TRUE(ctx.stopped());
    return outcomes;
  }
};

/* ---- plain cache behaviour (find/add, unchanged semantics) -------------- */

TEST_F(SecretCacheTest, FindMissThenAddHit)
{
  TokenEnvelope token;
  std::string secret;
  EXPECT_FALSE(cache->find("AKID", token, secret));
  EXPECT_EQ(0u, cache->size());

  cache->add("AKID", make_token("u"), "s3cr3t");
  ASSERT_TRUE(cache->find("AKID", token, secret));
  EXPECT_EQ("u", token.get_user_id());
  EXPECT_EQ("s3cr3t", secret);
  EXPECT_EQ(1u, cache->size());

  auto t = cache->find("AKID");
  ASSERT_TRUE(t);
  EXPECT_EQ("s3cr3t", t->get<1>());
}

TEST_F(SecretCacheTest, EntryExpiresAfterTtl)
{
  cache->add("AKID", make_token(), "s3cr3t");
  advance_clock(300);
  EXPECT_TRUE(cache->find("AKID"));   // now == expires is still valid
  advance_clock(1);
  EXPECT_FALSE(cache->find("AKID"));
  EXPECT_EQ(0u, cache->size());       // expired entries are erased
}

TEST_F(SecretCacheTest, ExpiredKeystoneTokenIsMiss)
{
  cache->add("AKID", make_token("u", /*expires=*/1), "s3cr3t");
  EXPECT_FALSE(cache->find("AKID"));
}

TEST_F(SecretCacheTest, LruEvictsOldest)
{
  set_conf("rgw_keystone_token_cache_size", "2");
  reset_cache();
  cache->add("a", make_token(), "sa");
  cache->add("b", make_token(), "sb");
  EXPECT_TRUE(cache->find("a"));      // touch a: b is now the oldest
  cache->add("c", make_token(), "sc");
  EXPECT_EQ(2u, cache->size());
  EXPECT_TRUE(cache->find("a"));
  EXPECT_FALSE(cache->find("b"));
  EXPECT_TRUE(cache->find("c"));
}

/* ---- get_or_fetch(): today's request path --------------------------------- */

TEST_F(SecretCacheTest, VerifiedHitIsServedWithoutFetch)
{
  cache->add("AKID", make_token(), "s3cr3t");
  FakeFetcher fetcher;
  const Outcome o = call(Request{}, fetcher, null_yield);
  EXPECT_TRUE(o.granted("s3cr3t"));
  EXPECT_EQ(0, fetcher.calls());
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_hit));
  EXPECT_EQ(0u, counter(l_rgw_keystone_secret_cache_miss));
}

TEST_F(SecretCacheTest, MissFetchesAndCaches)
{
  FakeFetcher fetcher;
  const Outcome o = call(Request{}, fetcher, null_yield);
  EXPECT_TRUE(o.granted("s3cr3t"));
  EXPECT_EQ(1, fetcher.calls());
  EXPECT_EQ(1u, cache->size());
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_miss));
  EXPECT_TRUE(call(Request{}, fetcher, null_yield).granted("s3cr3t"));
  EXPECT_EQ(1, fetcher.calls());
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_hit));
}

TEST_F(SecretCacheTest, MissFetchesAndCachesWithYield)
{
  FakeFetcher fetcher;
  const auto outcomes = run_coroutines({Request{}}, fetcher);
  EXPECT_TRUE(outcomes[0].granted("s3cr3t"));
  EXPECT_EQ(1, fetcher.calls());
  EXPECT_EQ(1u, cache->size());
}

TEST_F(SecretCacheTest, MismatchingSignatureFetchesAndReplaces)
{
  cache->add("AKID", make_token(), "old-secret");
  FakeFetcher fetcher;
  fetcher.set_script([] (int, const SignedSample&) { return ok_result("new-secret"); });
  Request req;
  req.expected_secret = "new-secret";
  const Outcome o = call(req, fetcher, null_yield);
  EXPECT_TRUE(o.granted("new-secret"));
  EXPECT_EQ(1, fetcher.calls());
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_miss));
  auto t = cache->find("AKID");
  ASSERT_TRUE(t);
  EXPECT_EQ("new-secret", t->get<1>());
}

TEST_F(SecretCacheTest, IgnoreSignatureHitSkipsVerification)
{
  cache->add("AKID", make_token(), "s3cr3t");
  FakeFetcher fetcher;
  Request req;
  req.expected_secret = "something-else";
  req.ignore_signature = true;
  EXPECT_TRUE(call(req, fetcher, null_yield).granted("s3cr3t"));
  EXPECT_EQ(0, fetcher.calls());
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_hit));
}

TEST_F(SecretCacheTest, SignatureMismatchFromKeystoneIsPassedThrough)
{
  FakeFetcher fetcher;
  fetcher.set_script([] (int, const SignedSample&) {
      return failed_result(-ERR_SIGNATURE_NO_MATCH); });
  EXPECT_TRUE(call(Request{}, fetcher, null_yield).denied(-ERR_SIGNATURE_NO_MATCH));
  EXPECT_EQ(0u, cache->size());
}

TEST_F(SecretCacheTest, InvalidAccessKeyFromKeystoneIsPassedThrough)
{
  FakeFetcher fetcher;
  fetcher.set_script([] (int, const SignedSample&) {
      return failed_result(-ERR_INVALID_ACCESS_KEY); });
  EXPECT_TRUE(call(Request{}, fetcher, null_yield).denied(-ERR_INVALID_ACCESS_KEY));
  EXPECT_EQ(0u, cache->size());
}

TEST_F(SecretCacheTest, TokenWithoutSecretIsPassedThroughUncached)
{
  FakeFetcher fetcher;
  fetcher.set_script([] (int, const SignedSample&) {
      return token_without_secret(-EACCES); });
  const Outcome o = call(Request{}, fetcher, null_yield);
  ASSERT_TRUE(o.result);
  EXPECT_TRUE(o.result->token);
  EXPECT_FALSE(o.result->secret_key);
  EXPECT_EQ(-EACCES, o.result->failure_reason);
  EXPECT_EQ(0u, cache->size());
}

TEST_F(SecretCacheTest, IntThrownByFetchIsRethrown)
{
  FakeFetcher fetcher;
  fetcher.set_script([] (int, const SignedSample&) -> FetchResult {
      throw -ERR_INTERNAL_ERROR; });
  const Outcome o = call(Request{}, fetcher, null_yield);
  ASSERT_TRUE(o.thrown_int);
  EXPECT_EQ(-ERR_INTERNAL_ERROR, *o.thrown_int);
  EXPECT_EQ(0u, cache->size());
}

TEST_F(SecretCacheTest, IntFoldedIntoResultIsRethrown)
{
  FakeFetcher fetcher;
  fetcher.set_script([] (int, const SignedSample&) {
      FetchResult r;
      r.thrown = -EBUSY;
      return r; });
  const Outcome o = call(Request{}, fetcher, null_yield);
  ASSERT_TRUE(o.thrown_int);
  EXPECT_EQ(-EBUSY, *o.thrown_int);
}

TEST_F(SecretCacheTest, ExceptionThrownByFetchIsRethrown)
{
  FakeFetcher fetcher;
  fetcher.set_script([] (int, const SignedSample&) -> FetchResult {
      throw std::runtime_error("boom"); });
  const Outcome o = call(Request{}, fetcher, null_yield);
  ASSERT_TRUE(o.eptr);
  EXPECT_THROW(std::rethrow_exception(o.eptr), std::runtime_error);
}

} // anonymous namespace

int main(int argc, char** argv)
{
  auto args = argv_to_vec(argc, argv);
  std::map<std::string, std::string> defaults{{"debug_rgw", "20"}};
  auto cct = global_init(&defaults, args, CEPH_ENTITY_TYPE_CLIENT,
                         CODE_ENVIRONMENT_UTILITY,
                         CINIT_FLAG_NO_DEFAULT_CONFIG_FILE);
  common_init_finish(g_ceph_context);
  rgw_perf_start(g_ceph_context);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
