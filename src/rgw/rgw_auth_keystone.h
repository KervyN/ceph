// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#pragma once

#include <exception>
#include <functional>
#include <list>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <boost/optional.hpp>

#include "include/function2.hpp"
#include "common/Clock.h"

#include "rgw_auth.h"
#include "rgw_rest_s3.h"
#include "rgw_common.h"
#include "rgw_keystone.h"

namespace rgw {
namespace auth {
namespace keystone {

/* Dedicated namespace for Keystone-related auth engines. We need it because
 * Keystone offers three different authentication mechanisms (token, EC2 and
 * regular user/pass). RadosGW actually does support the first two. */

class TokenEngine : public rgw::auth::Engine {
  CephContext* const cct;

  using acl_strategy_t = rgw::auth::RemoteApplier::acl_strategy_t;
  using auth_info_t = rgw::auth::RemoteApplier::AuthInfo;
  using result_t = rgw::auth::Engine::result_t;
  using token_envelope_t = rgw::keystone::TokenEnvelope;

  const rgw::auth::TokenExtractor* const auth_token_extractor;
  const rgw::auth::TokenExtractor* const service_token_extractor;
  const rgw::auth::RemoteApplier::Factory* const apl_factory;
  rgw::keystone::Config& config;
  rgw::keystone::TokenCache& token_cache;

  /* Helper methods. */
  bool is_applicable(const std::string& token) const noexcept;

  boost::optional<token_envelope_t>
  get_from_keystone(const DoutPrefixProvider* dpp,
                    const std::string& token,
                    bool allow_expired,
                    optional_yield y) const;

  acl_strategy_t get_acl_strategy(const token_envelope_t& token) const;
  auth_info_t get_creds_info(const token_envelope_t& token) const noexcept;
  result_t authenticate(const DoutPrefixProvider* dpp,
                        const std::string& token,
                        const std::string& service_token,
                        const req_state* s,
                        optional_yield y) const;

public:
  TokenEngine(CephContext* const cct,
              const rgw::auth::TokenExtractor* const auth_token_extractor,
              const rgw::auth::TokenExtractor* const service_token_extractor,
              const rgw::auth::RemoteApplier::Factory* const apl_factory,
              rgw::keystone::Config& config,
              rgw::keystone::TokenCache& token_cache)
    : cct(cct),
      auth_token_extractor(auth_token_extractor),
      service_token_extractor(service_token_extractor),
      apl_factory(apl_factory),
      config(config),
      token_cache(token_cache) {
  }

  const char* get_name() const noexcept override {
    return "rgw::auth::keystone::TokenEngine";
  }

  result_t authenticate(const DoutPrefixProvider* dpp, const req_state* const s,
			optional_yield y) const override {
    return authenticate(dpp, auth_token_extractor->get_token(s),
                        service_token_extractor->get_token(s), s, y);
  }
}; /* class TokenEngine */

/* The client-signed sample that Keystone validates through /v3/s3tokens.
 * Owned strings, so that a lookup can outlive the request that supplied
 * them. */
struct SignedSample {
  std::string access_key_id;
  std::string string_to_sign;
  std::string signature;
};

/* Outcome of one Keystone credential lookup: POST /v3/s3tokens followed by
 * GET /v3/users/{id}/credentials/OS-EC2/{access_key_id}.
 *
 * CredentialFetcher::get_token() throws an int for failures other than
 * 401/404. `thrown` carries that int and `eptr` any other exception, so
 * that one result can be handed to several callers and rethrown by each
 * of them. The type is semiregular on purpose. */
struct FetchResult {
  boost::optional<rgw::keystone::TokenEnvelope> token;
  boost::optional<std::string> secret;
  int failure_reason = 0;
  std::optional<int> thrown;
  std::exception_ptr eptr;
};

/* Fetches S3 credentials from Keystone. Holds only process-lifetime state
 * (the CephContext and the Config/TokenCache singletons), so copies of it
 * may be used by work that outlives the EC2Engine: the auth registry, and
 * with it the engine, is rebuilt on every realm reload. */
class CredentialFetcher {
  CephContext* const cct;
  const rgw::keystone::Config& config;
  rgw::keystone::TokenCache& token_cache;

public:
  CredentialFetcher(CephContext* const cct,
                    const rgw::keystone::Config& config,
                    rgw::keystone::TokenCache& token_cache) noexcept
    : cct(cct),
      config(config),
      token_cache(token_cache) {
  }

  /* Validate the sample against /v3/s3tokens. Returns the token envelope,
   * -ERR_SIGNATURE_NO_MATCH for 401 or -ERR_INVALID_ACCESS_KEY for 404.
   * Throws an int for any other failure. A timeout_secs of 0 keeps the
   * libcurl defaults. */
  std::pair<boost::optional<rgw::keystone::TokenEnvelope>, int>
  get_token(const DoutPrefixProvider* dpp,
            const SignedSample& sample,
            optional_yield y,
            long timeout_secs = 0) const;

  /* Fetch the secret of access_key_id from /v3/users/{user_id}/credentials.
   * Never throws; 404 is reported as -ERR_INVALID_ACCESS_KEY. */
  std::pair<boost::optional<std::string>, int>
  get_secret(const DoutPrefixProvider* dpp,
             std::string_view user_id,
             std::string_view access_key_id,
             optional_yield y,
             long timeout_secs = 0) const;

  /* Both lookups. Exceptions are folded into the result, except for the
   * one boost.context uses to unwind a coroutine that is being destroyed. */
  FetchResult fetch(const DoutPrefixProvider* dpp,
                    const SignedSample& sample,
                    optional_yield y,
                    long timeout_secs = 0) const;
}; /* class CredentialFetcher */

/* Per-process cache of Keystone-validated S3 credentials, keyed by access
 * key id. Besides the plain find()/add() API it owns the policy that
 * EC2Engine applies on every request (get_or_fetch()), which keeps that
 * policy unit-testable with a fake fetcher and a fake clock. */
class SecretCache {
public:
  using token_envelope_t = rgw::keystone::TokenEnvelope;

  /* Performs the Keystone lookup for a sample. Must be copyable and must
   * not reference request-scoped state. */
  using fetch_fn = std::function<FetchResult(const DoutPrefixProvider* dpp,
                                             const SignedSample& sample,
                                             optional_yield y,
                                             long timeout_secs)>;
  /* Tells whether the request's signature verifies against a secret. */
  using verify_fn = fu2::function_view<bool(const std::string& secret)>;
  using clock_fn = utime_t (*)();

  /* What EC2Engine::authenticate() destructures: exactly these three
   * members. */
  struct access_result {
    boost::optional<token_envelope_t> token;
    boost::optional<std::string> secret_key;
    int failure_reason = 0;
  };

private:
  struct secret_entry {
    token_envelope_t token;
    std::string secret;
    utime_t expires;
    std::list<std::string>::iterator lru_iter;
  };

  struct lookup_result {
    bool found = false;
    token_envelope_t token;
    std::string secret;
  };

  const boost::intrusive_ptr<CephContext> cct;

  std::map<std::string, secret_entry> secrets;
  std::list<std::string> secrets_lru;

  std::mutex lock;

  const size_t max;

  const utime_t s3_token_expiry_length;

  clock_fn now_fn = ceph_clock_now;

  SecretCache() : SecretCache(g_ceph_context) {}

  lookup_result lookup(const std::string& access_key_id);
  void erase_locked(std::map<std::string, secret_entry>::iterator iter);

  /* Run fetch() and cache a complete result. Folds an int thrown by
   * fetch() into the result. */
  FetchResult fetch_and_add(const DoutPrefixProvider* dpp,
                            const SignedSample& sample,
                            const fetch_fn& fetch,
                            optional_yield y,
                            long timeout_secs);
  /* Rethrows what fetch() threw, otherwise converts. */
  static access_result to_access_result(FetchResult&& r);

public:
  explicit SecretCache(CephContext* const cct);
  ~SecretCache() {}

  SecretCache(const SecretCache&) = delete;
  void operator=(const SecretCache&) = delete;

  static SecretCache& get_instance() {
    /* In C++11 this is thread safe. */
    static SecretCache instance;
    return instance;
  }

  bool find(const std::string& token_id, token_envelope_t& token, std::string& secret);
  boost::optional<boost::tuple<token_envelope_t, std::string>> find(const std::string& token_id) {
    token_envelope_t token_envlp;
    std::string secret;
    if (find(token_id, token_envlp, secret)) {
      return boost::make_tuple(token_envlp, secret);
    }
    return boost::none;
  }
  void add(const std::string& token_id, const token_envelope_t& token, const std::string& secret);

  /* Serve the sample from the cache when its signature verifies against
   * the cached secret, otherwise validate it against Keystone with fetch()
   * and cache the outcome. Rethrows the int (or exception) that fetch()
   * threw, exactly where the uncached path would have thrown it. */
  access_result get_or_fetch(const DoutPrefixProvider* dpp,
                             const SignedSample& sample,
                             verify_fn verify,
                             bool ignore_signature,
                             const fetch_fn& fetch,
                             optional_yield y);

  /* Test seams. */
  void set_clock_for_testing(clock_fn now) noexcept { now_fn = now; }
  size_t size();
}; /* class SecretCache */

class EC2Engine : public rgw::auth::s3::AWSEngine {
  using acl_strategy_t = rgw::auth::RemoteApplier::acl_strategy_t;
  using auth_info_t = rgw::auth::RemoteApplier::AuthInfo;
  using result_t = rgw::auth::Engine::result_t;
  using token_envelope_t = rgw::keystone::TokenEnvelope;
  using access_token_result = SecretCache::access_result;

  const rgw::auth::RemoteApplier::Factory* const apl_factory;
  rgw::auth::keystone::SecretCache& secret_cache;
  const CredentialFetcher fetcher;
  /* Wraps `fetcher`; built once so that the request path does not
   * allocate a std::function per call. */
  const SecretCache::fetch_fn fetch_fn;

  /* Helper methods. */
  acl_strategy_t get_acl_strategy(const token_envelope_t& token) const;
  auth_info_t get_creds_info(const token_envelope_t& token,
                             const std::vector<std::string>& admin_roles,
                             const std::string& access_key_id
                            ) const noexcept;

  access_token_result
  get_access_token(const DoutPrefixProvider* dpp,
                   const std::string_view& access_key_id,
                   const std::string& string_to_sign,
                   const std::string_view& signature,
		   const signature_factory_t& signature_factory,
                   bool ignore_signature,
                   optional_yield y) const;
  result_t authenticate(const DoutPrefixProvider* dpp,
                        const std::string_view& access_key_id,
                        const std::string_view& signature,
                        const std::string_view& session_token,
                        const string_to_sign_t& string_to_sign,
                        const signature_factory_t& signature_factory,
                        const completer_factory_t& completer_factory,
                        const req_state* s,
			optional_yield y) const override;
public:
  EC2Engine(CephContext* const cct,
            const rgw::auth::s3::AWSEngine::VersionAbstractor* const ver_abstractor,
            const rgw::auth::RemoteApplier::Factory* const apl_factory,
            rgw::keystone::Config& config,
            /* The token cache is used ONLY for the retrieving admin token.
             * Due to the architecture of AWS Auth S3 credentials cannot be
             * cached at all. */
            rgw::keystone::TokenCache& token_cache,
	    rgw::auth::keystone::SecretCache& secret_cache)
    : AWSEngine(cct, *ver_abstractor),
      apl_factory(apl_factory),
      secret_cache(secret_cache),
      fetcher(cct, config, token_cache),
      fetch_fn([fetcher = this->fetcher] (const DoutPrefixProvider* dpp,
                                           const SignedSample& sample,
                                           optional_yield y,
                                           long timeout_secs) {
                 return fetcher.fetch(dpp, sample, y, timeout_secs);
               }) {
  }

  using AWSEngine::authenticate;

  const char* get_name() const noexcept override {
    return "rgw::auth::keystone::EC2Engine";
  }

}; /* class EC2Engine */

}; /* namespace keystone */
}; /* namespace auth */
}; /* namespace rgw */
