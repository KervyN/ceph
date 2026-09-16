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
 * The gate holds a fetch that arrives while hold(call_no) says so: a
 * coroutine suspends on its own yield_waiter, a thread blocks on the
 * condition variable. open_gate() releases all of them, release_next() the
 * oldest one. */
class FakeFetcher {
  struct Parked {
    std::unique_ptr<ceph::async::yield_waiter<void>> waiter;  // coroutine
    bool released = false;                                    // thread
  };
  struct State {
    std::atomic<int> calls{0};
    std::atomic<int> concurrent{0};
    std::atomic<int> max_concurrent{0};
    std::function<FetchResult(int call_no, const SignedSample&)> script;

    std::mutex mutex;
    std::function<bool(int call_no)> hold;
    std::condition_variable cond;
    std::list<std::shared_ptr<Parked>> parked;
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
  /* hold the fetches for which pred(call_no) is true */
  void hold_calls(std::function<bool(int)> pred)
  {
    std::lock_guard l{st->mutex};
    st->hold = std::move(pred);
  }
  void close_gate()
  {
    hold_calls([] (int) { return true; });
  }
  void open_gate()
  {
    std::list<std::shared_ptr<Parked>> parked;
    {
      std::lock_guard l{st->mutex};
      st->hold = nullptr;
      parked.swap(st->parked);
    }
    for (auto& p : parked) {
      release(*p);
    }
  }
  void release_next()
  {
    std::shared_ptr<Parked> p;
    {
      std::lock_guard l{st->mutex};
      ASSERT_FALSE(st->parked.empty());
      p = std::move(st->parked.front());
      st->parked.pop_front();
    }
    release(*p);
  }
  int calls() const { return st->calls.load(); }
  int max_concurrent() const { return st->max_concurrent.load(); }
  std::vector<long> timeouts() const
  {
    std::lock_guard l{st->mutex};
    return st->timeouts;
  }
  /* number of fetches currently parked at the gate */
  size_t parked() const
  {
    std::lock_guard l{st->mutex};
    return st->parked.size();
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
    wait_at_gate(call_no, y);
    --st->concurrent;
    return st->script(call_no, sample);
  }

 private:
  void release(Parked& p)
  {
    if (p.waiter) {
      p.waiter->complete(boost::system::error_code{});
    } else {
      std::lock_guard l{st->mutex};
      p.released = true;
      st->cond.notify_all();
    }
  }

  void wait_at_gate(int call_no, optional_yield y) const
  {
    std::unique_lock l{st->mutex};
    if (!st->hold || !st->hold(call_no)) {
      return;
    }
    auto p = st->parked.emplace_back(std::make_shared<Parked>());
    if (y) {
      p->waiter = std::make_unique<ceph::async::yield_waiter<void>>();
      /* releases the lock right before the coroutine suspends */
      p->waiter->async_wait(l, y.get_yield_context());
    } else {
      st->cond.wait(l, [&] { return p->released; });
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

  void TearDown() override
  {
    set_conf("rgw_keystone_token_cache_coalesce_misses", "false");
    set_conf("rgw_keystone_token_cache_refresh_enabled", "false");
    set_conf("rgw_keystone_token_cache_refresh_before", "30");
    set_conf("rgw_keystone_token_cache_refresh_max_concurrent", "16");
    set_conf("rgw_keystone_token_cache_ttl_jitter", "0");
  }

  /* the cache snapshots size and ttl in its constructor */
  void reset_cache()
  {
    cache = std::make_unique<SecretCache>(cct);
    cache->set_clock_for_testing(fake_clock);
  }

  void enable_coalescing()
  {
    set_conf("rgw_keystone_token_cache_coalesce_misses", "true");
  }

  void enable_refresh()
  {
    set_conf("rgw_keystone_token_cache_refresh_enabled", "true");
  }

  /* cache "AKID" -> s3cr3t and move the clock into the refresh window
   * (ttl 300, refresh_before 30: 25 seconds of lifetime left) */
  void cache_entry_near_expiry(const std::string& akid = "AKID",
                               const std::string& secret = "s3cr3t")
  {
    cache->add(akid, make_token(), secret);
    advance_clock(275);
  }

  /* spawn one request on ctx and run it until it completes or suspends */
  void spawn_request(boost::asio::io_context& ctx, Outcome& out,
                     Request req, const FakeFetcher& fetcher)
  {
    boost::asio::spawn(ctx, [this, &out, &fetcher, req = std::move(req)]
        (boost::asio::yield_context yield) {
          out = call(req, fetcher, optional_yield{yield});
        }, [] (std::exception_ptr eptr) {
          if (eptr) std::rethrow_exception(eptr);
        });
    step(ctx);
  }

  static void drain(boost::asio::io_context& ctx)
  {
    ctx.restart();
    ctx.run();
  }

  static std::vector<Request> requests(size_t n, const Request& req = Request{})
  {
    return std::vector<Request>(n, req);
  }

  static size_t count_granted(const std::vector<Outcome>& outcomes,
                              const std::string& secret)
  {
    size_t n = 0;
    for (const auto& o : outcomes) {
      n += o.granted(secret);
    }
    return n;
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

  using parked_fn = std::function<void(boost::asio::io_context&)>;

  /* N requests as coroutines on one io_context, driven single-threaded
   * (deterministic). while_parked() runs after poll() with everything
   * suspended, typically to open the fetcher's gate; step() lets it run
   * the context in between. */
  std::vector<Outcome> run_coroutines(const std::vector<Request>& reqs,
                                      const FakeFetcher& fetcher,
                                      const parked_fn& while_parked = {})
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
      while_parked(ctx);
      ctx.restart();
      ctx.run();
    }
    EXPECT_TRUE(ctx.stopped());
    return outcomes;
  }

  static void step(boost::asio::io_context& ctx)
  {
    ctx.restart();
    ctx.poll();
  }

  /* N request coroutines on an io_context run by `threads` OS threads */
  std::vector<Outcome> run_coroutines_threaded(const std::vector<Request>& reqs,
                                               const FakeFetcher& fetcher,
                                               int threads)
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
    {
      std::vector<std::jthread> runners;
      for (int i = 0; i < threads; ++i) {
        runners.emplace_back([&ctx] { ctx.run(); });
      }
    }
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

/* ---- coalescing of concurrent misses ----------------------------------- */

TEST_F(SecretCacheTest, CoalescingIsOffByDefault)
{
  FakeFetcher fetcher;
  fetcher.close_gate();
  const auto outcomes = run_coroutines(requests(8), fetcher, [&] (auto&) {
      EXPECT_EQ(8u, fetcher.parked());   // every request talks to Keystone
      fetcher.open_gate();
    });
  EXPECT_EQ(8, fetcher.calls());
  EXPECT_EQ(8u, count_granted(outcomes, "s3cr3t"));
  EXPECT_EQ(0u, counter(l_rgw_keystone_secret_cache_coalesced));
}

TEST_F(SecretCacheTest, Coalesce2000ParallelMissesFetchOnce)
{
  enable_coalescing();
  FakeFetcher fetcher;
  fetcher.close_gate();
  const auto outcomes = run_coroutines(requests(2000), fetcher, [&] (auto&) {
      EXPECT_EQ(1, fetcher.calls());
      EXPECT_EQ(1u, fetcher.parked());
      fetcher.open_gate();
    });
  EXPECT_EQ(1, fetcher.calls());
  EXPECT_EQ(2000u, count_granted(outcomes, "s3cr3t"));
  EXPECT_EQ(1999u, counter(l_rgw_keystone_secret_cache_coalesced));
  EXPECT_EQ(2000u, counter(l_rgw_keystone_secret_cache_miss));
  EXPECT_EQ(0u, cache->inflight_size());
  EXPECT_EQ(1u, cache->size());
}

TEST_F(SecretCacheTest, CoalesceParallelMissesOnIoThreads)
{
  enable_coalescing();
  FakeFetcher fetcher;
  const auto outcomes = run_coroutines_threaded(requests(500), fetcher, 4);
  EXPECT_EQ(1, fetcher.calls());
  EXPECT_EQ(500u, count_granted(outcomes, "s3cr3t"));
  EXPECT_EQ(0u, cache->inflight_size());
}

TEST_F(SecretCacheTest, CoalesceParallelMissesOnThreadsNullYield)
{
  enable_coalescing();
  FakeFetcher fetcher;
  fetcher.close_gate();
  const auto outcomes = run_threads(requests(64), fetcher, [&] {
      /* let most threads reach the flight before releasing the leader */
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      fetcher.open_gate();
    });
  EXPECT_EQ(1, fetcher.calls());
  EXPECT_EQ(64u, count_granted(outcomes, "s3cr3t"));
  EXPECT_EQ(0u, cache->inflight_size());
}

TEST_F(SecretCacheTest, CoalescedWaiterVerifiesOwnSignature)
{
  enable_coalescing();
  FakeFetcher fetcher;
  fetcher.set_script([] (int, const SignedSample& s) {
      return s.signature == "bad" ? failed_result(-ERR_SIGNATURE_NO_MATCH) : ok_result(); });
  fetcher.close_gate();
  std::vector<Request> reqs = requests(3);
  reqs[2].sample.signature = "bad";
  reqs[2].expected_secret = "nothing-verifies";
  const auto outcomes = run_coroutines(reqs, fetcher, [&] (auto&) { fetcher.open_gate(); });
  EXPECT_TRUE(outcomes[0].granted("s3cr3t"));
  EXPECT_TRUE(outcomes[1].granted("s3cr3t"));
  /* the mismatching waiter does not inherit the grant: Keystone judges
   * its own sample, as it does for a mismatching cache hit */
  EXPECT_TRUE(outcomes[2].denied(-ERR_SIGNATURE_NO_MATCH));
  EXPECT_EQ(2, fetcher.calls());
}

TEST_F(SecretCacheTest, OptionsRequestsBypassCoalescing)
{
  enable_coalescing();
  FakeFetcher fetcher;
  fetcher.close_gate();
  std::vector<Request> reqs = requests(3);
  reqs[1].ignore_signature = true;   // has no signature to verify a shared secret with
  reqs[2].ignore_signature = true;
  /* the OPTIONS misses fetch on their own, as today, even while a flight is open */
  const auto outcomes = run_coroutines(reqs, fetcher, [&] (auto&) {
      EXPECT_EQ(3u, fetcher.parked());
      EXPECT_EQ(1u, cache->inflight_size());
      fetcher.open_gate();
    });
  EXPECT_EQ(3, fetcher.calls());
  EXPECT_EQ(3u, count_granted(outcomes, "s3cr3t"));
  EXPECT_EQ(0u, counter(l_rgw_keystone_secret_cache_coalesced));
}

TEST_F(SecretCacheTest, DistinctAccessKeysCoalesceIndependently)
{
  enable_coalescing();
  FakeFetcher fetcher;
  fetcher.set_script([] (int, const SignedSample& s) {
      return ok_result("secret-" + s.access_key_id); });
  fetcher.close_gate();
  std::vector<Request> reqs;
  for (int i = 0; i < 20; ++i) {
    const std::string akid = i % 2 ? "A" : "B";
    reqs.push_back(Request{make_sample(akid), "secret-" + akid});
  }
  const auto outcomes = run_coroutines(reqs, fetcher, [&] (auto&) {
      EXPECT_EQ(2u, fetcher.parked());
      EXPECT_EQ(2u, cache->inflight_size());
      fetcher.open_gate();
    });
  EXPECT_EQ(2, fetcher.calls());
  EXPECT_EQ(10u, count_granted(outcomes, "secret-A"));
  EXPECT_EQ(10u, count_granted(outcomes, "secret-B"));
  EXPECT_EQ(18u, counter(l_rgw_keystone_secret_cache_coalesced));
  EXPECT_EQ(0u, cache->inflight_size());
  EXPECT_EQ(2u, cache->size());
}

TEST_F(SecretCacheTest, Leader401IsNotInheritedWaitersRetryOnce)
{
  enable_coalescing();
  FakeFetcher fetcher;
  fetcher.set_script([] (int call_no, const SignedSample&) {
      return call_no == 1 ? failed_result(-ERR_SIGNATURE_NO_MATCH) : ok_result(); });
  fetcher.close_gate();
  std::vector<Request> reqs = requests(11);
  reqs[0].sample.signature = "bad";
  reqs[0].expected_secret = "nothing-verifies";
  const auto outcomes = run_coroutines(reqs, fetcher, [&] (auto&) { fetcher.open_gate(); });
  EXPECT_TRUE(outcomes[0].denied(-ERR_SIGNATURE_NO_MATCH));
  EXPECT_EQ(10u, count_granted(outcomes, "s3cr3t"));
  EXPECT_EQ(2, fetcher.calls());          // one for the bad leader, one for the rest
  EXPECT_EQ(1, fetcher.max_concurrent()); // never in parallel
  EXPECT_EQ(0u, cache->inflight_size());
}

TEST_F(SecretCacheTest, WaitersFallBackToDirectFetchAfterTwoRounds)
{
  enable_coalescing();
  FakeFetcher fetcher;
  fetcher.set_script([] (int call_no, const SignedSample& s) {
      return s.signature == "bad" ? failed_result(-ERR_SIGNATURE_NO_MATCH) : ok_result(); });
  fetcher.close_gate();
  std::vector<Request> reqs = requests(4);
  for (int i = 0; i < 3; ++i) {
    reqs[i].sample.signature = "bad";
    reqs[i].expected_secret = "nothing-verifies";
  }
  const auto outcomes = run_coroutines(reqs, fetcher, [&] (auto& ctx) {
      fetcher.release_next();  // bad leader 1 gets 401
      step(ctx);               // bad 2 leads the next round, bad 3 and good wait
      fetcher.release_next();  // bad leader 2 gets 401
      step(ctx);               // bad 3 and good have waited twice: both fetch directly
      EXPECT_EQ(2u, fetcher.parked());
      fetcher.open_gate();
    });
  EXPECT_TRUE(outcomes[0].denied(-ERR_SIGNATURE_NO_MATCH));
  EXPECT_TRUE(outcomes[1].denied(-ERR_SIGNATURE_NO_MATCH));
  EXPECT_TRUE(outcomes[2].denied(-ERR_SIGNATURE_NO_MATCH));
  EXPECT_TRUE(outcomes[3].granted("s3cr3t"));
  EXPECT_EQ(4, fetcher.calls());
  EXPECT_EQ(2, fetcher.max_concurrent());  // the two direct fetches overlapped
}

TEST_F(SecretCacheTest, InvalidAccessKeyIsSharedByWaiters)
{
  enable_coalescing();
  FakeFetcher fetcher;
  fetcher.set_script([] (int, const SignedSample&) {
      return failed_result(-ERR_INVALID_ACCESS_KEY); });
  fetcher.close_gate();
  const auto outcomes = run_coroutines(requests(50), fetcher, [&] (auto&) { fetcher.open_gate(); });
  EXPECT_EQ(1, fetcher.calls());
  for (const auto& o : outcomes) {
    EXPECT_TRUE(o.denied(-ERR_INVALID_ACCESS_KEY));
  }
  EXPECT_EQ(49u, counter(l_rgw_keystone_secret_cache_coalesced));
  EXPECT_EQ(0u, cache->size());
}

TEST_F(SecretCacheTest, ThrownIntIsSharedByWaitersAndNotSticky)
{
  enable_coalescing();
  FakeFetcher fetcher;
  fetcher.set_script([] (int call_no, const SignedSample&) -> FetchResult {
      if (call_no == 1) throw -ERR_INTERNAL_ERROR;
      return ok_result(); });
  fetcher.close_gate();
  const auto outcomes = run_coroutines(requests(50), fetcher, [&] (auto&) { fetcher.open_gate(); });
  EXPECT_EQ(1, fetcher.calls());
  for (const auto& o : outcomes) {
    ASSERT_TRUE(o.thrown_int);
    EXPECT_EQ(-ERR_INTERNAL_ERROR, *o.thrown_int);
  }
  EXPECT_EQ(0u, cache->inflight_size());
  /* the error was not cached: the next miss contacts Keystone again */
  EXPECT_TRUE(call(Request{}, fetcher, null_yield).granted("s3cr3t"));
  EXPECT_EQ(2, fetcher.calls());
}

TEST_F(SecretCacheTest, ThrownIntIsSharedByThreadsNullYield)
{
  enable_coalescing();
  FakeFetcher fetcher;
  fetcher.set_script([] (int, const SignedSample&) -> FetchResult {
      throw -EBUSY; });
  fetcher.close_gate();
  const auto outcomes = run_threads(requests(16), fetcher, [&] {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      fetcher.open_gate();
    });
  EXPECT_EQ(1, fetcher.calls());
  for (const auto& o : outcomes) {
    ASSERT_TRUE(o.thrown_int);
    EXPECT_EQ(-EBUSY, *o.thrown_int);
  }
}

TEST_F(SecretCacheTest, NonStandardExceptionIsSharedByWaiters)
{
  /* once_result only catches std::exception; anything else must be folded
   * before it gets there or the waiters would never wake up */
  enable_coalescing();
  FakeFetcher fetcher;
  fetcher.set_script([] (int, const SignedSample&) -> FetchResult { throw 42u; });
  fetcher.close_gate();
  const auto outcomes = run_coroutines(requests(20), fetcher, [&] (auto&) { fetcher.open_gate(); });
  EXPECT_EQ(1, fetcher.calls());
  for (const auto& o : outcomes) {
    ASSERT_TRUE(o.eptr);
    EXPECT_THROW(std::rethrow_exception(o.eptr), unsigned);
  }
  EXPECT_EQ(0u, cache->inflight_size());
}

TEST_F(SecretCacheTest, ExceptionIsSharedByWaiters)
{
  enable_coalescing();
  FakeFetcher fetcher;
  fetcher.set_script([] (int, const SignedSample&) -> FetchResult {
      throw std::runtime_error("boom"); });
  fetcher.close_gate();
  const auto outcomes = run_coroutines(requests(5), fetcher, [&] (auto&) { fetcher.open_gate(); });
  EXPECT_EQ(1, fetcher.calls());
  for (const auto& o : outcomes) {
    ASSERT_TRUE(o.eptr);
    EXPECT_THROW(std::rethrow_exception(o.eptr), std::runtime_error);
  }
  EXPECT_EQ(0u, cache->inflight_size());
}

TEST_F(SecretCacheTest, TokenWithoutSecretIsNotInheritedByWaiters)
{
  enable_coalescing();
  FakeFetcher fetcher;
  fetcher.set_script([] (int call_no, const SignedSample&) {
      return call_no == 1 ? token_without_secret(-EACCES) : ok_result(); });
  fetcher.close_gate();
  const auto outcomes = run_coroutines(requests(6), fetcher, [&] (auto&) { fetcher.open_gate(); });
  /* the leader keeps today's outcome: token, no secret */
  ASSERT_TRUE(outcomes[0].result);
  EXPECT_TRUE(outcomes[0].result->token);
  EXPECT_FALSE(outcomes[0].result->secret_key);
  /* the waiters could not verify anything and looked again */
  EXPECT_EQ(5u, count_granted(outcomes, "s3cr3t"));
  EXPECT_EQ(2, fetcher.calls());
}

TEST_F(SecretCacheTest, MissWhileFlightOpenJoinsIt)
{
  enable_coalescing();
  FakeFetcher fetcher;
  fetcher.close_gate();
  boost::asio::io_context ctx;
  Outcome first, second;
  boost::asio::spawn(ctx, [&] (boost::asio::yield_context yield) {
        first = call(Request{}, fetcher, optional_yield{yield});
      }, [] (std::exception_ptr) {});
  ctx.poll();
  EXPECT_EQ(1u, cache->inflight_size());
  boost::asio::spawn(ctx, [&] (boost::asio::yield_context yield) {
        second = call(Request{}, fetcher, optional_yield{yield});
      }, [] (std::exception_ptr) {});
  ctx.restart();
  ctx.poll();
  EXPECT_EQ(1, fetcher.calls());
  fetcher.open_gate();
  ctx.restart();
  ctx.run();
  EXPECT_TRUE(first.granted("s3cr3t"));
  EXPECT_TRUE(second.granted("s3cr3t"));
  EXPECT_EQ(1, fetcher.calls());
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_coalesced));
}

/* ---- asynchronous early refresh ----------------------------------------- */

TEST_F(SecretCacheTest, RefreshIsOffByDefault)
{
  cache_entry_near_expiry();
  FakeFetcher fetcher;
  const auto outcomes = run_coroutines(requests(5), fetcher);
  EXPECT_EQ(5u, count_granted(outcomes, "s3cr3t"));
  EXPECT_EQ(0, fetcher.calls());
  EXPECT_EQ(0u, counter(l_rgw_keystone_secret_cache_refresh));
}

TEST_F(SecretCacheTest, RefreshStartsOnceAndNeverBlocksRequests)
{
  enable_refresh();
  cache_entry_near_expiry();
  FakeFetcher fetcher;
  fetcher.set_script([] (int, const SignedSample&) { return ok_result("fresh"); });
  fetcher.close_gate();
  const auto outcomes = run_coroutines(requests(100), fetcher, [&] (auto&) {
      /* every request was answered while the refresh is still parked */
      EXPECT_EQ(100u, counter(l_rgw_keystone_secret_cache_hit));
      EXPECT_EQ(1u, fetcher.parked());
      EXPECT_EQ(1, fetcher.calls());
      EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_refresh));
      EXPECT_EQ(1u, cache->refreshes_in_flight());
      fetcher.open_gate();
    });
  EXPECT_EQ(100u, count_granted(outcomes, "s3cr3t"));   // the old secret
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_refresh_ok));
  EXPECT_EQ(0u, cache->refreshes_in_flight());
  EXPECT_EQ(0u, cache->inflight_size());
  auto t = cache->find("AKID");
  ASSERT_TRUE(t);
  EXPECT_EQ("fresh", t->get<1>());
  EXPECT_EQ(std::vector<long>{30}, fetcher.timeouts());  // bounded by refresh_before
}

TEST_F(SecretCacheTest, RefreshedEntryIsRefreshedAgainInTheNextWindow)
{
  enable_refresh();
  cache_entry_near_expiry();
  FakeFetcher fetcher;
  run_coroutines(requests(1), fetcher);
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_refresh_ok));
  advance_clock(200);                 // 75 s into the refreshed entry: not yet
  run_coroutines(requests(1), fetcher);
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_refresh));
  advance_clock(80);                  // 20 s left
  run_coroutines(requests(1), fetcher);
  EXPECT_EQ(2u, counter(l_rgw_keystone_secret_cache_refresh));
  EXPECT_EQ(2, fetcher.calls());
}

TEST_F(SecretCacheTest, RefreshNotStartedOutsideTheWindow)
{
  enable_refresh();
  cache->add("AKID", make_token(), "s3cr3t");
  advance_clock(269);                 // 31 s left
  FakeFetcher fetcher;
  run_coroutines(requests(3), fetcher);
  EXPECT_EQ(0u, counter(l_rgw_keystone_secret_cache_refresh));
  advance_clock(1);                   // 30 s left: at the threshold
  run_coroutines(requests(1), fetcher);
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_refresh));
}

TEST_F(SecretCacheTest, RefreshBeforeIsClampedToHalfTtl)
{
  enable_refresh();
  set_conf("rgw_keystone_token_cache_refresh_before", "1000");
  cache->add("AKID", make_token(), "s3cr3t");
  FakeFetcher fetcher;
  advance_clock(100);                 // 200 s left > 150
  run_coroutines(requests(1), fetcher);
  EXPECT_EQ(0u, counter(l_rgw_keystone_secret_cache_refresh));
  advance_clock(50);                  // 150 s left
  run_coroutines(requests(1), fetcher);
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_refresh));
}

TEST_F(SecretCacheTest, RefreshWindowUsesKeystoneTokenExpiryWhenEarlier)
{
  enable_refresh();
  /* TokenEnvelope::expired() reads the real clock: align the fake one */
  fake_now_secs = ::time(nullptr);
  cache->add("AKID", make_token("u", fake_now_secs + 20), "s3cr3t");
  FakeFetcher fetcher;
  run_coroutines(requests(1), fetcher);   // 300 s of cache ttl, 20 s of token
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_refresh));
}

TEST_F(SecretCacheTest, OptionsHitDoesNotStartRefresh)
{
  enable_refresh();
  cache_entry_near_expiry();
  FakeFetcher fetcher;
  Request req;
  req.ignore_signature = true;
  run_coroutines(requests(3, req), fetcher);
  EXPECT_EQ(0u, counter(l_rgw_keystone_secret_cache_refresh));
  EXPECT_EQ(0, fetcher.calls());
}

TEST_F(SecretCacheTest, MismatchingHitDoesNotStartRefresh)
{
  enable_refresh();
  cache_entry_near_expiry();
  FakeFetcher fetcher;
  fetcher.set_script([] (int, const SignedSample&) {
      return failed_result(-ERR_SIGNATURE_NO_MATCH); });
  Request req;
  req.expected_secret = "wrong";
  const auto outcomes = run_coroutines(requests(1, req), fetcher);
  EXPECT_TRUE(outcomes[0].denied(-ERR_SIGNATURE_NO_MATCH));
  EXPECT_EQ(1, fetcher.calls());       // the request's own lookup
  EXPECT_EQ(0u, counter(l_rgw_keystone_secret_cache_refresh));
}

TEST_F(SecretCacheTest, NullYieldHitSkipsRefreshOncePerEntry)
{
  enable_refresh();
  cache_entry_near_expiry();
  FakeFetcher fetcher;
  EXPECT_TRUE(call(Request{}, fetcher, null_yield).granted("s3cr3t"));
  EXPECT_TRUE(call(Request{}, fetcher, null_yield).granted("s3cr3t"));
  EXPECT_EQ(0, fetcher.calls());
  EXPECT_EQ(0u, counter(l_rgw_keystone_secret_cache_refresh));
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_refresh_skipped));
}

TEST_F(SecretCacheTest, TransientRefreshFailureKeepsEntryAndIsNotRetried)
{
  enable_refresh();
  cache_entry_near_expiry();
  FakeFetcher fetcher;
  fetcher.set_script([] (int call_no, const SignedSample&) -> FetchResult {
      if (call_no == 1) throw -ERR_INTERNAL_ERROR;   // 429 at the nginx
      return ok_result("fresh"); });
  auto outcomes = run_coroutines(requests(5), fetcher);
  EXPECT_EQ(5u, count_granted(outcomes, "s3cr3t"));
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_refresh));
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_refresh_failed));
  EXPECT_EQ(1u, cache->size());
  /* more hits inside the window: no second attempt for this entry */
  outcomes = run_coroutines(requests(5), fetcher);
  EXPECT_EQ(5u, count_granted(outcomes, "s3cr3t"));
  EXPECT_EQ(1, fetcher.calls());
  /* the entry expires as usual and the miss fetches */
  advance_clock(30);
  outcomes = run_coroutines(requests(1), fetcher);
  EXPECT_TRUE(outcomes[0].granted("fresh"));
  EXPECT_EQ(2, fetcher.calls());
}

TEST_F(SecretCacheTest, Refresh401KeepsEntryUntilExpiry)
{
  /* a 401 also happens when the admin token is stale: evicting on it
   * would turn an admin token hiccup into a full cache flush */
  enable_refresh();
  cache_entry_near_expiry();
  FakeFetcher fetcher;
  fetcher.set_script([] (int, const SignedSample&) {
      return failed_result(-ERR_SIGNATURE_NO_MATCH); });
  const auto outcomes = run_coroutines(requests(1), fetcher);
  EXPECT_TRUE(outcomes[0].granted("s3cr3t"));
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_refresh_failed));
  EXPECT_EQ(0u, counter(l_rgw_keystone_secret_cache_refresh_evicted));
  EXPECT_EQ(1u, cache->size());
  advance_clock(25);
  EXPECT_TRUE(cache->find("AKID"));
  advance_clock(1);
  EXPECT_FALSE(cache->find("AKID"));
}

TEST_F(SecretCacheTest, RefreshFindingCredentialDeletedEvictsEntry)
{
  enable_refresh();
  for (const FetchResult& rejected : {failed_result(-ERR_INVALID_ACCESS_KEY),
                                      token_without_secret(-ERR_INVALID_ACCESS_KEY)}) {
    perfcounter->reset();
    reset_cache();
    cache_entry_near_expiry();
    FakeFetcher fetcher;
    fetcher.set_script([rejected] (int, const SignedSample&) { return rejected; });
    const auto outcomes = run_coroutines(requests(1), fetcher);
    EXPECT_TRUE(outcomes[0].granted("s3cr3t"));   // served before the verdict
    EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_refresh_evicted));
    EXPECT_EQ(0u, cache->size());
  }
}

TEST_F(SecretCacheTest, RefreshVerdictIsDroppedWhenEntryWasReplaced)
{
  enable_refresh();
  cache_entry_near_expiry("AKID", "old");
  FakeFetcher fetcher;
  fetcher.set_script([] (int call_no, const SignedSample&) {
      return call_no == 1 ? failed_result(-ERR_INVALID_ACCESS_KEY) : ok_result("new"); });
  fetcher.hold_calls([] (int call_no) { return call_no == 1; });

  boost::asio::io_context ctx;
  Outcome hit, rotated;
  Request req;
  req.expected_secret = "old";
  spawn_request(ctx, hit, req, fetcher);          // starts the refresh (call 1, parked)
  EXPECT_EQ(1u, cache->refreshes_in_flight());
  req.expected_secret = "new";
  spawn_request(ctx, rotated, req, fetcher);      // mismatch: fetches the rotated secret
  EXPECT_TRUE(rotated.granted("new"));
  fetcher.open_gate();
  drain(ctx);

  EXPECT_TRUE(hit.granted("old"));
  EXPECT_EQ(0u, counter(l_rgw_keystone_secret_cache_refresh_evicted));
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_refresh_skipped));
  auto t = cache->find("AKID");
  ASSERT_TRUE(t);
  EXPECT_EQ("new", t->get<1>());                  // the rotated secret survived
}

TEST_F(SecretCacheTest, RefreshResultIsDroppedWhenEntryWasReplaced)
{
  enable_refresh();
  cache_entry_near_expiry("AKID", "old");
  FakeFetcher fetcher;
  fetcher.set_script([] (int call_no, const SignedSample&) {
      return call_no == 1 ? ok_result("stale") : ok_result("new"); });
  fetcher.hold_calls([] (int call_no) { return call_no == 1; });

  boost::asio::io_context ctx;
  Outcome hit, rotated;
  Request req;
  req.expected_secret = "old";
  spawn_request(ctx, hit, req, fetcher);          // starts the refresh (call 1, parked)
  req.expected_secret = "new";
  spawn_request(ctx, rotated, req, fetcher);      // mismatch: fetches the rotated secret
  EXPECT_TRUE(rotated.granted("new"));
  fetcher.open_gate();
  drain(ctx);

  EXPECT_EQ(0u, counter(l_rgw_keystone_secret_cache_refresh_ok));
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_refresh_skipped));
  auto t = cache->find("AKID");
  ASSERT_TRUE(t);
  EXPECT_EQ("new", t->get<1>());                  // not overwritten by the older fetch
}

TEST_F(SecretCacheTest, MissDuringRefreshJoinsItsFlight)
{
  enable_refresh();
  enable_coalescing();
  cache_entry_near_expiry();
  FakeFetcher fetcher;
  fetcher.set_script([] (int, const SignedSample&) { return ok_result("fresh"); });
  fetcher.close_gate();

  boost::asio::io_context ctx;
  Outcome hit;
  spawn_request(ctx, hit, Request{}, fetcher);    // refresh parked
  advance_clock(30);                              // the entry expires meanwhile
  std::vector<Outcome> misses(20);
  Request req;
  req.expected_secret = "fresh";
  for (auto& o : misses) {
    spawn_request(ctx, o, req, fetcher);          // miss: joins the refresh's flight
  }
  EXPECT_EQ(1, fetcher.calls());
  fetcher.open_gate();
  drain(ctx);

  EXPECT_TRUE(hit.granted("s3cr3t"));
  EXPECT_EQ(20u, count_granted(misses, "fresh"));
  EXPECT_EQ(1, fetcher.calls());
  EXPECT_EQ(20u, counter(l_rgw_keystone_secret_cache_coalesced));
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_refresh_ok));
}

TEST_F(SecretCacheTest, RefreshSkipsWhenARequestIsValidatingTheKey)
{
  enable_refresh();
  enable_coalescing();
  cache_entry_near_expiry("AKID", "old");
  FakeFetcher fetcher;
  fetcher.set_script([] (int, const SignedSample&) { return ok_result("new"); });
  fetcher.close_gate();

  boost::asio::io_context ctx;
  Outcome rotated, hit;
  Request req;
  req.expected_secret = "new";
  spawn_request(ctx, rotated, req, fetcher);      // mismatch: leads a flight, parked
  req.expected_secret = "old";
  spawn_request(ctx, hit, req, fetcher);          // verified hit: refresh armed
  EXPECT_TRUE(hit.granted("old"));
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_refresh));
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_refresh_skipped));
  EXPECT_EQ(1, fetcher.calls());
  fetcher.open_gate();
  drain(ctx);
  EXPECT_TRUE(rotated.granted("new"));
  EXPECT_EQ(0u, cache->refreshes_in_flight());
}

TEST_F(SecretCacheTest, RefreshConcurrencyIsCapped)
{
  enable_refresh();
  set_conf("rgw_keystone_token_cache_refresh_max_concurrent", "1");
  cache->add("A", make_token(), "sa");
  cache->add("B", make_token(), "sb");
  advance_clock(275);                             // both are due
  FakeFetcher fetcher;
  fetcher.close_gate();

  boost::asio::io_context ctx;
  Outcome a, b;
  spawn_request(ctx, a, Request{make_sample("A"), "sa"}, fetcher);
  spawn_request(ctx, b, Request{make_sample("B"), "sb"}, fetcher);
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_refresh));
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_refresh_skipped));
  EXPECT_EQ(1u, cache->refreshes_in_flight());
  fetcher.open_gate();
  drain(ctx);
  EXPECT_EQ(0u, cache->refreshes_in_flight());

  /* B is still due and a later hit starts its refresh */
  spawn_request(ctx, b, Request{make_sample("B"), "sb"}, fetcher);
  drain(ctx);
  EXPECT_EQ(2u, counter(l_rgw_keystone_secret_cache_refresh));
  EXPECT_EQ(2u, counter(l_rgw_keystone_secret_cache_refresh_ok));
}

TEST_F(SecretCacheTest, LruEvictionDuringRefreshIsHarmless)
{
  set_conf("rgw_keystone_token_cache_size", "1");
  reset_cache();
  enable_refresh();
  cache_entry_near_expiry("A", "sa");
  FakeFetcher fetcher;
  fetcher.set_script([] (int, const SignedSample&) { return ok_result("sa2"); });
  fetcher.close_gate();

  boost::asio::io_context ctx;
  Outcome a;
  spawn_request(ctx, a, Request{make_sample("A"), "sa"}, fetcher);
  cache->add("B", make_token(), "sb");            // evicts A
  EXPECT_FALSE(cache->find("A"));
  fetcher.open_gate();
  drain(ctx);
  EXPECT_EQ(1u, counter(l_rgw_keystone_secret_cache_refresh_ok));
  EXPECT_EQ(1u, cache->size());
  auto t = cache->find("A");
  ASSERT_TRUE(t);
  EXPECT_EQ("sa2", t->get<1>());
}

TEST_F(SecretCacheTest, RefreshFetchExceptionsCountAsFailures)
{
  /* both are folded by run_fetch(); run_refresh()'s own handlers are a
   * last line of defence that nothing reaches in practice */
  enable_refresh();
  uint64_t n = 0;
  for (auto script : {
      std::function<FetchResult(int, const SignedSample&)>(
          [] (int, const SignedSample&) -> FetchResult { throw std::logic_error("bug"); }),
      std::function<FetchResult(int, const SignedSample&)>(
          [] (int, const SignedSample&) -> FetchResult { throw 42u; })}) {
    reset_cache();
    cache_entry_near_expiry();
    FakeFetcher fetcher;
    fetcher.set_script(script);
    const auto outcomes = run_coroutines(requests(1), fetcher);
    EXPECT_TRUE(outcomes[0].granted("s3cr3t"));
    EXPECT_EQ(++n, counter(l_rgw_keystone_secret_cache_refresh_failed));
    EXPECT_EQ(0u, cache->refreshes_in_flight());
    EXPECT_EQ(1u, cache->size());
  }
}

/* ---- ttl jitter ----------------------------------------------------------- */

TEST_F(SecretCacheTest, JitterShortensLifetimeWithinBounds)
{
  set_conf("rgw_keystone_token_cache_ttl_jitter", "60");
  const int n = 300;
  for (int i = 0; i < n; ++i) {
    cache->add("k" + std::to_string(i), make_token(), "s");
  }
  auto present = [&] {
    int count = 0;
    for (int i = 0; i < n; ++i) {
      count += bool(cache->find("k" + std::to_string(i)));
    }
    return count;
  };
  advance_clock(240);
  EXPECT_EQ(n, present());            // lifetime is at least ttl - jitter
  advance_clock(30);
  const int halfway = present();      // 270 s: the jitter spreads the expiries
  EXPECT_GT(halfway, 0);
  EXPECT_LT(halfway, n);
  advance_clock(31);
  EXPECT_EQ(0, present());            // and never lengthens them
}

TEST_F(SecretCacheTest, JitterIsClampedToHalfTtl)
{
  set_conf("rgw_keystone_token_cache_ttl_jitter", "1000");
  for (int i = 0; i < 100; ++i) {
    cache->add("k" + std::to_string(i), make_token(), "s");
  }
  advance_clock(150);
  for (int i = 0; i < 100; ++i) {
    EXPECT_TRUE(cache->find("k" + std::to_string(i)));
  }
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
