// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#include <string>
#include <vector>

#include <errno.h>
#include <fnmatch.h>

#include <boost/asio/spawn.hpp>
#include <boost/context/detail/exception.hpp>
#include <boost/context/protected_fixedsize_stack.hpp>

#include "rgw_b64.h"

#include "common/errno.h"
#include "common/ceph_json.h"
#include "include/random.h"
#include "include/types.h"
#include "include/str_list.h"

#include "rgw_common.h"
#include "rgw_keystone.h"
#include "rgw_keystone_scope.h"
#include "rgw_auth_keystone.h"
#include "rgw_rest_s3.h"
#include "rgw_auth_s3.h"
#include "rgw_perf_counters.h"

#include "common/ceph_crypto.h"
#include "common/Cond.h"

#define dout_subsys ceph_subsys_rgw

using namespace std;

namespace rgw {
namespace auth {
namespace keystone {

bool
TokenEngine::is_applicable(const std::string& token) const noexcept
{
  return ! token.empty() && ! cct->_conf->rgw_keystone_url.empty();
}

boost::optional<TokenEngine::token_envelope_t>
TokenEngine::get_from_keystone(const DoutPrefixProvider* dpp,
                               const std::string& token,
                               bool allow_expired,
                               optional_yield y) const
{
  /* Unfortunately, we can't use the short form of "using" here. It's because
   * we're aliasing a class' member, not namespace. */
  using RGWValidateKeystoneToken = \
    rgw::keystone::Service::RGWValidateKeystoneToken;

  bool admin_token_retried = false;

admin_token_retry:

  /* The container for plain response obtained from Keystone. It will be
   * parsed token_envelope_t::parse method. */
  ceph::bufferlist token_body_bl;
  RGWValidateKeystoneToken validate(cct, "GET", "", &token_body_bl);

  std::string url = config.get_endpoint_url();
  if (url.empty()) {
    throw -EINVAL;
  }

  url.append("v3/auth/tokens");

  if (allow_expired) {
    url.append("?allow_expired=1");
  }

  validate.append_header("X-Subject-Token", token);

  std::string admin_token;
  bool admin_token_cached = false;
  int ret = rgw::keystone::Service::get_admin_token(dpp, token_cache, config,
                                                    y, admin_token, admin_token_cached);
  if (ret < 0) {
    throw -EINVAL;
  }

  if (allow_expired) {
    validate.append_header("X-Auth-Token", admin_token);
  } else {
    validate.append_header("X-Auth-Token", token);
  }

  validate.set_send_length(0);

  validate.set_url(url);

  ret = validate.process(dpp, y);

  /* NULL terminate for debug output. */
  token_body_bl.append(static_cast<char>(0));

  /* Detect Keystone rejection earlier than during the token parsing.
   * Although failure at the parsing phase doesn't impose a threat,
   * this allows to return proper error code (EACCESS instead of EINVAL
   * or similar) and thus improves logging. */

  /* If admin token is invalid we should expire it from the cache and
     try one last time without the cache. */
  bool admin_token_unauthorized = (validate.get_http_status() ==
    RGWValidateKeystoneToken::HTTP_STATUS_UNAUTHORIZED);

  if (admin_token_unauthorized && admin_token_cached) {
    ldpp_dout(dpp, 20) << "invalidating admin_token cache due to 401" << dendl;
    token_cache.invalidate_admin(dpp);

    if (!admin_token_retried) {
      ldpp_dout(dpp, 20) << "retrying with uncached admin_token" << dendl;
      admin_token_retried = true;
      goto admin_token_retry;
    }
  }

  /* If admin token is invalid or token supplied by client is non-existent. */
  if (admin_token_unauthorized || validate.get_http_status() ==
        RGWValidateKeystoneToken::HTTP_STATUS_NOTFOUND) {
    ldpp_dout(dpp, 5) << "Failed keystone auth from " << url << " with "
                  << validate.get_http_status() << dendl;
    return boost::none;
  }
  // throw any other http or connection errors
  if (ret < 0) {
    throw ret;
  }

  ldpp_dout(dpp, 20) << "received response status=" << validate.get_http_status()
                 << ", body=" << token_body_bl.c_str() << dendl;

  TokenEngine::token_envelope_t token_body;
  ret = token_body.parse(dpp, token, token_body_bl);
  if (ret < 0) {
    throw ret;
  }

  return token_body;
}

TokenEngine::auth_info_t
TokenEngine::get_creds_info(const TokenEngine::token_envelope_t& token
                           ) const noexcept
{
  using acct_privilege_t = rgw::auth::RemoteApplier::AuthInfo::acct_privilege_t;
  std::vector<std::string> role_names;

  /* Check whether the user has an admin status. */
  acct_privilege_t level = acct_privilege_t::IS_PLAIN_ACCT;
  for (const auto& role : token.roles) {
    role_names.push_back(role.name);
    if (role.is_admin && !role.is_reader) {
      level = acct_privilege_t::IS_ADMIN_ACCT;
    }
  }

  /* Build keystone scope info if ops logging is enabled */
  auto keystone_scope = rgw::keystone::build_scope_info(cct, token);

  return auth_info_t {
    /* Suggested account name for the authenticated user. */
    rgw_user(token.get_project_id()),
    /* User's display name (aka real name). */
    token.get_project_name(),
    /* Keystone doesn't support RGW's subuser concept, so we cannot cut down
     * the access rights through the perm_mask. At least at this layer. */
    RGW_PERM_FULL_CONTROL,
    level,
    rgw::auth::RemoteApplier::AuthInfo::NO_ACCESS_KEY,
    rgw::auth::RemoteApplier::AuthInfo::NO_SUBUSER,
    token.get_user_name(),
    TYPE_KEYSTONE,
    std::move(keystone_scope),
    std::move(role_names),
    token.get_user_id()
  };
}

static inline const std::string
make_spec_item(const std::string& tenant, const std::string& id)
{
  return tenant + ":" + id;
}

TokenEngine::acl_strategy_t
TokenEngine::get_acl_strategy(const TokenEngine::token_envelope_t& token) const
{
  /* The primary identity is constructed upon UUIDs. */
  const auto& tenant_uuid = token.get_project_id();
  const auto& user_uuid = token.get_user_id();

  /* For Keystone v2 an alias may be also used. */
  const auto& tenant_name = token.get_project_name();
  const auto& user_name = token.get_user_name();

  /* Construct all possible combinations including Swift's wildcards. */
  const std::array<std::string, 6> allowed_items = {
    make_spec_item(tenant_uuid, user_uuid),
    make_spec_item(tenant_name, user_name),

    /* Wildcards. */
    make_spec_item(tenant_uuid, "*"),
    make_spec_item(tenant_name, "*"),
    make_spec_item("*", user_uuid),
    make_spec_item("*", user_name),
  };

  /* Lambda will obtain a copy of (not a reference to!) allowed_items. */
  return [allowed_items, token_roles=token.roles](const rgw::auth::Identity::aclspec_t& aclspec) {
    uint32_t perm = 0;

    for (const auto& allowed_item : allowed_items) {
      const auto iter = aclspec.find(allowed_item);

      if (std::end(aclspec) != iter) {
        perm |= iter->second;
      }
    }

    for (const auto& r : token_roles) {
      if (r.is_reader) {
        if (r.is_admin) {    /* system scope reader persona */
          /*
           * Because system reader defeats permissions,
           * we don't even look at the aclspec.
           */
          perm |= RGW_OP_TYPE_READ;
        }
      }
    }

    return perm;
  };
}

TokenEngine::result_t
TokenEngine::authenticate(const DoutPrefixProvider* dpp,
                          const std::string& token,
                          const std::string& service_token,
                          const req_state* const s,
                          optional_yield y) const
{
  bool allow_expired = false;
  boost::optional<TokenEngine::token_envelope_t> t;

  /* This will be initialized on the first call to this method. In C++11 it's
   * also thread-safe. */
  static const struct RolesCacher {
    explicit RolesCacher(CephContext* const cct) {
      get_str_vec(cct->_conf->rgw_keystone_accepted_roles, plain);
      get_str_vec(cct->_conf->rgw_keystone_accepted_admin_roles, admin);
      get_str_vec(cct->_conf->rgw_keystone_accepted_reader_roles, reader);

      /* Let's suppose that having an admin role implies also a regular one. */
      plain.insert(std::end(plain), std::begin(admin), std::end(admin));
    }

    std::vector<std::string> plain;
    std::vector<std::string> admin;
    std::vector<std::string> reader;
  } roles(cct);

  static const struct ServiceTokenRolesCacher {
    explicit ServiceTokenRolesCacher(CephContext* const cct) {
      get_str_vec(cct->_conf->rgw_keystone_service_token_accepted_roles, plain);
    }

    std::vector<std::string> plain;
  } service_token_roles(cct);

  if (! is_applicable(token)) {
    return result_t::deny();
  }

  /* Token ID is a legacy of supporting the service-side validation
   * of PKI/PKIz token type which are already-removed-in-OpenStack.
   * The idea was to bury in cache only a short hash instead of few
   * kilobytes. RadosGW doesn't do the local validation anymore. */
  const auto& token_id = rgw_get_token_id(token);
  ldpp_dout(dpp, 20) << "token_id=" << token_id << dendl;

  /* Check cache first. */
  t = token_cache.find(token_id);
  if (t) {
    ldpp_dout(dpp, 20) << "cached token.project.id=" << t->get_project_id()
                   << dendl;
    auto apl = apl_factory->create_apl_remote(cct, s, get_acl_strategy(*t),
                                              get_creds_info(*t));
    return result_t::grant(std::move(apl));
  }

  /* We have a service token and a token so we verify the service
   * token and if it's invalid the request is invalid. If it's valid
   * we allow an expired token to be used when doing lookup in Keystone.
   * We never get to this if the token is in the cache. */
  if (g_conf()->rgw_keystone_service_token_enabled && ! service_token.empty()) {
    boost::optional<TokenEngine::token_envelope_t> st;

    const auto& service_token_id = rgw_get_token_id(service_token);
    ldpp_dout(dpp, 20) << "service_token_id=" << service_token_id << dendl;

    /* Check cache for service token first. */
    st = token_cache.find_service(service_token_id);
    if (st) {
      ldpp_dout(dpp, 20) << "cached service_token.project.id=" << st->get_project_id()
                     << dendl;

      /* We found the service token in the cache so we allow using an expired
       * token for this request. */
      allow_expired = true;
      ldpp_dout(dpp, 20) << "allowing expired tokens because service_token_id="
                     << service_token_id
                     << " was found in cache" << dendl;
    } else {
      /* Service token was not found in cache. Go to Keystone for validating
       * the token. The allow_expired here must always be false. */
      ceph_assert(allow_expired == false);
      st = get_from_keystone(dpp, service_token, allow_expired, y);

      if (! st) {
        return result_t::deny(-EACCES);
      }

      /* Verify expiration of service token. */
      if (st->expired()) {
        ldpp_dout(dpp, 0) << "got expired service token: " << st->get_project_name()
                       << ":" << st->get_user_name()
                       << " expired " << st->get_expires() << dendl;
        return result_t::deny(-EPERM);
      }

      /* Check for necessary roles for service token. */
      for (const auto& role : service_token_roles.plain) {
        if (st->has_role(role) == true) {
          /* Service token is valid so we allow using an expired token for
           * this request. */
          ldpp_dout(dpp, 20) << "allowing expired tokens because service_token_id="
                         << service_token_id
                         << " is valid, role: "
                         << role << dendl;
          allow_expired = true;
          token_cache.add_service(service_token_id, *st);
          break;
        }
      }

      if (!allow_expired) {
        ldpp_dout(dpp, 0) << "service token user does not hold a matching role; required roles: "
                  << g_conf()->rgw_keystone_service_token_accepted_roles << dendl;
        return result_t::deny(-EPERM);
      }
    }
  }

  /* Token not in cache. Go to the Keystone for validation. This happens even
   * for the legacy PKI/PKIz token types. That's it, after the PKI/PKIz
   * RadosGW-side validation has been removed, we always ask Keystone. */
  t = get_from_keystone(dpp, token, allow_expired, y);
  if (! t) {
    return result_t::deny(-EACCES);
  }
  t->update_roles(roles.admin, roles.reader);

  /* Verify expiration. */
  if (t->expired()) {
    if (allow_expired) {
      ldpp_dout(dpp, 20) << "allowing expired token: " << t->get_project_name()
                    << ":" << t->get_user_name()
                    << " expired: " << t->get_expires()
                    << " because of valid service token" << dendl;
    } else {
      ldpp_dout(dpp, 0) << "got expired token: " << t->get_project_name()
                    << ":" << t->get_user_name()
                    << " expired: " << t->get_expires() << dendl;
      return result_t::deny(-EPERM);
    }
  }

  /* Check for necessary roles. */
  for (const auto& role : roles.plain) {
    if (t->has_role(role) == true) {
      /* If this token was an allowed expired token because we got a
       * service token we need to update the expiration before we cache it. */
      if (allow_expired) {
        time_t now = ceph_clock_now().sec();
        time_t new_expires = now + g_conf()->rgw_keystone_expired_token_cache_expiration;
        ldpp_dout(dpp, 20) << "updating expiration of allowed expired token"
                           << " from old " << t->get_expires() << " to now " << now << " + "
                           << g_conf()->rgw_keystone_expired_token_cache_expiration
                           << " secs = "
                           << new_expires << dendl;
        t->set_expires(new_expires);
      }
      ldpp_dout(dpp, 0) << "validated token: " << t->get_project_name()
                    << ":" << t->get_user_name()
                    << " expires: " << t->get_expires() << dendl;
      token_cache.add(token_id, *t);
      auto apl = apl_factory->create_apl_remote(cct, s, get_acl_strategy(*t),
                                                get_creds_info(*t));
      return result_t::grant(std::move(apl));
    }
  }

  ldpp_dout(dpp, 0) << "user does not hold a matching role; required roles: "
                << g_conf()->rgw_keystone_accepted_roles << dendl;

  return result_t::deny(-EPERM);
}


static void set_timeout(RGWHTTPClient& client, const long timeout_secs)
{
  if (timeout_secs > 0) {
    client.set_req_timeout(timeout_secs);
    client.set_req_connect_timeout(timeout_secs);
  }
}

/*
 * Try to validate S3 auth against keystone s3token interface
 */
std::pair<boost::optional<rgw::keystone::TokenEnvelope>, int>
CredentialFetcher::get_token(const DoutPrefixProvider* dpp,
                             const SignedSample& sample,
                             optional_yield y,
                             const long timeout_secs) const
{
  /* prepare keystone url */
  std::string keystone_url = config.get_endpoint_url();
  if (keystone_url.empty()) {
    throw -EINVAL;
  }

  keystone_url.append("v3/s3tokens");

  /* get authentication token for Keystone. */
  std::string admin_token;
  bool admin_token_cached = false;
  int ret = rgw::keystone::Service::get_admin_token(dpp, token_cache, config,
                                                    y, admin_token, admin_token_cached);
  if (ret < 0) {
    ldpp_dout(dpp, 2) << "s3 keystone: cannot get token for keystone access"
                  << dendl;
    throw ret;
  }

  using RGWValidateKeystoneToken
    = rgw::keystone::Service::RGWValidateKeystoneToken;

  /* The container for plain response obtained from Keystone. It will be
   * parsed token_envelope_t::parse method. */
  ceph::bufferlist token_body_bl;
  RGWValidateKeystoneToken validate(cct, "POST", keystone_url, &token_body_bl);

  /* set required headers for keystone request */
  validate.append_header("X-Auth-Token", admin_token);
  validate.append_header("Content-Type", "application/json");

  /* check if we want to verify keystone's ssl certs */
  validate.set_verify_ssl(cct->_conf->rgw_keystone_verify_ssl);
  set_timeout(validate, timeout_secs);

  /* create json credentials request body */
  JSONFormatter credentials(false);
  credentials.open_object_section("");
  credentials.open_object_section("credentials");
  credentials.dump_string("access", sample.access_key_id);
  credentials.dump_string("token", rgw::to_base64(sample.string_to_sign));
  credentials.dump_string("signature", sample.signature);
  credentials.close_section();
  credentials.close_section();

  std::stringstream os;
  credentials.flush(os);
  validate.set_post_data(os.str());
  validate.set_send_length(os.str().length());

  /* send request */
  ret = validate.process(dpp, y);

  /* if the supplied signature is wrong, we will get 401 from Keystone */
  if (validate.get_http_status() ==
          decltype(validate)::HTTP_STATUS_UNAUTHORIZED) {
    return std::make_pair(boost::none, -ERR_SIGNATURE_NO_MATCH);
  } else if (validate.get_http_status() ==
          decltype(validate)::HTTP_STATUS_NOTFOUND) {
    return std::make_pair(boost::none, -ERR_INVALID_ACCESS_KEY);
  }
  // throw any other http or connection errors
  if (ret < 0) {
    ldpp_dout(dpp, 2) << "s3 keystone: token validation ERROR: "
                  << token_body_bl.c_str() << dendl;
    throw ret;
  }

  /* now parse response */
  rgw::keystone::TokenEnvelope token_envelope;
  ret = token_envelope.parse(dpp, std::string(), token_body_bl);
  if (ret < 0) {
    ldpp_dout(dpp, 2) << "s3 keystone: token parsing failed, ret=0" << ret
                  << dendl;
    throw ret;
  }

  return std::make_pair(std::move(token_envelope), 0);
}

auto CredentialFetcher::get_secret(const DoutPrefixProvider* dpp,
                                   const std::string_view user_id,
                                   const std::string_view access_key_id,
                                   optional_yield y,
                                   const long timeout_secs) const
    -> std::pair<boost::optional<std::string>, int>
{
  /*  Fetch from /users/{USER_ID}/credentials/OS-EC2/{ACCESS_KEY_ID} */
  /* Should return json with response key "credential" which contains entry "secret"*/

  /* prepare keystone url */
  std::string keystone_url = config.get_endpoint_url();
  if (keystone_url.empty()) {
    return make_pair(boost::none, -EINVAL);
  }

  keystone_url.append("v3/");
  keystone_url.append("users/");
  keystone_url.append(user_id);
  keystone_url.append("/credentials/OS-EC2/");
  keystone_url.append(access_key_id);

  /* get authentication token for Keystone. */
  std::string admin_token;
  bool admin_token_cached = false;
  int ret = rgw::keystone::Service::get_admin_token(dpp, token_cache, config,
                                                    y, admin_token, admin_token_cached);
  if (ret < 0) {
    ldpp_dout(dpp, 2) << "s3 keystone: cannot get token for keystone access"
                  << dendl;
    return make_pair(boost::none, ret);
  }

  using RGWGetAccessSecret
    = rgw::keystone::Service::RGWKeystoneHTTPTransceiver;

  /* The container for plain response obtained from Keystone.*/
  ceph::bufferlist token_body_bl;
  RGWGetAccessSecret secret(cct, "GET", keystone_url, &token_body_bl);

  /* set required headers for keystone request */
  secret.append_header("X-Auth-Token", admin_token);

  /* check if we want to verify keystone's ssl certs */
  secret.set_verify_ssl(cct->_conf->rgw_keystone_verify_ssl);
  set_timeout(secret, timeout_secs);

  /* send request */
  ret = secret.process(dpp, y);

  /* if the supplied access key isn't found, we will get 404 from Keystone */
  if (secret.get_http_status() ==
          decltype(secret)::HTTP_STATUS_NOTFOUND) {
    return make_pair(boost::none, -ERR_INVALID_ACCESS_KEY);
  }
  // return any other http or connection errors
  if (ret < 0) {
    ldpp_dout(dpp, 2) << "s3 keystone: secret fetching error: "
                  << token_body_bl.c_str() << dendl;
    return make_pair(boost::none, ret);
  }

  /* now parse response */

  JSONParser parser;
  if (! parser.parse(token_body_bl.c_str(), token_body_bl.length())) {
    ldpp_dout(dpp, 0) << "Keystone credential parse error: malformed json" << dendl;
    return make_pair(boost::none, -EINVAL);
  }

  JSONObjIter credential_iter = parser.find_first("credential");
  std::string secret_string;

  try {
    if (!credential_iter.end()) {
      JSONDecoder::decode_json("secret", secret_string, *credential_iter, true);
    } else {
      ldpp_dout(dpp, 0) << "Keystone credential not present in return from server" << dendl;
      return make_pair(boost::none, -EINVAL);
    }
  } catch (const JSONDecoder::err& err) {
    ldpp_dout(dpp, 0) << "Keystone credential parse error: " << err.what() << dendl;
    return make_pair(boost::none, -EINVAL);
  }

  return make_pair(secret_string, 0);
}

FetchResult CredentialFetcher::fetch(const DoutPrefixProvider* dpp,
                                     const SignedSample& sample,
                                     optional_yield y,
                                     const long timeout_secs) const
{
  FetchResult r;
  try {
    std::tie(r.token, r.failure_reason) =
        get_token(dpp, sample, y, timeout_secs);

    if (r.token) {
      /* Fetch secret from keystone for the access_key_id */
      std::tie(r.secret, r.failure_reason) =
          get_secret(dpp, r.token->get_user_id(), sample.access_key_id, y,
                     timeout_secs);
    }
  } catch (const int err) {
    r.thrown = err;
  } catch (const boost::context::detail::forced_unwind&) {
    throw;  // a suspended coroutine is being destroyed: let it unwind
  } catch (...) {
    r.eptr = std::current_exception();
  }
  return r;
}

/*
 * Try to get a token for S3 authentication, using a secret cache if available
 */
auto EC2Engine::get_access_token(const DoutPrefixProvider* dpp,
                                 const std::string_view& access_key_id,
                                 const std::string& string_to_sign,
                                 const std::string_view& signature,
                                 const signature_factory_t& signature_factory,
                                 bool ignore_signature,
                                 optional_yield y) const
    -> access_token_result
{
  using server_signature_t = VersionAbstractor::server_signature_t;
  const SignedSample sample{std::string(access_key_id), string_to_sign,
                            std::string(signature)};

  /* Check that credentials can correctly be used to sign data */
  const auto verify = [&] (const std::string& secret) {
    const server_signature_t server_signature =
        signature_factory(cct, secret, string_to_sign);
    return sample.signature.compare(server_signature) == 0;
  };

  return secret_cache.get_or_fetch(dpp, sample, verify, ignore_signature,
                                   fetch_fn, y);
}

EC2Engine::acl_strategy_t
EC2Engine::get_acl_strategy(const EC2Engine::token_envelope_t&) const
{
  /* This is based on the assumption that the default acl strategy in
   * get_perms_from_aclspec, will take care. Extra acl spec is not required. */
  return nullptr;
}

EC2Engine::auth_info_t
EC2Engine::get_creds_info(const EC2Engine::token_envelope_t& token,
                          const std::vector<std::string>& admin_roles,
                          const std::string& access_key_id
                         ) const noexcept
{
  using acct_privilege_t = \
    rgw::auth::RemoteApplier::AuthInfo::acct_privilege_t;

  /* Check whether the user has an admin status. */
  acct_privilege_t level = acct_privilege_t::IS_PLAIN_ACCT;
  for (const auto& admin_role : admin_roles) {
    if (token.has_role(admin_role)) {
      level = acct_privilege_t::IS_ADMIN_ACCT;
      break;
    }
  }

  /* Build keystone scope info if ops logging is enabled */
  auto keystone_scope = rgw::keystone::build_scope_info(cct, token);

  std::vector<std::string> role_names;
  for (const auto& role : token.roles) {
    role_names.push_back(role.name);
  }

  return auth_info_t {
    /* Suggested account name for the authenticated user. */
    rgw_user(token.get_project_id()),
    /* User's display name (aka real name). */
    token.get_project_name(),
    /* Keystone doesn't support RGW's subuser concept, so we cannot cut down
     * the access rights through the perm_mask. At least at this layer. */
    RGW_PERM_FULL_CONTROL,
    level,
    access_key_id,
    rgw::auth::RemoteApplier::AuthInfo::NO_SUBUSER,
    token.get_user_name(),
    TYPE_KEYSTONE,
    std::move(keystone_scope),
    std::move(role_names),
    token.get_user_id()
  };
}

rgw::auth::Engine::result_t EC2Engine::authenticate(
  const DoutPrefixProvider* dpp,
  const std::string_view& access_key_id,
  const std::string_view& signature,
  const std::string_view& session_token,
  const string_to_sign_t& string_to_sign,
  const signature_factory_t& signature_factory,
  const completer_factory_t& completer_factory,
  const req_state* s,
  optional_yield y) const
{
  /* This will be initialized on the first call to this method. In C++11 it's
   * also thread-safe. */
  static const struct RolesCacher {
    explicit RolesCacher(CephContext* const cct) {
      get_str_vec(cct->_conf->rgw_keystone_accepted_roles, plain);
      get_str_vec(cct->_conf->rgw_keystone_accepted_admin_roles, admin);

      /* Let's suppose that having an admin role implies also a regular one. */
      plain.insert(std::end(plain), std::begin(admin), std::end(admin));
    }

    std::vector<std::string> plain;
    std::vector<std::string> admin;
  } accepted_roles(cct);

  /* When we handle a HTTP OPTIONS call we must ignore the signature */
  bool ignore_signature = (s->op_type == RGW_OP_OPTIONS_CORS);

  auto [t, secret_key, failure_reason] =
    get_access_token(dpp, access_key_id, string_to_sign,
                     signature, signature_factory, ignore_signature, y);
  if (! t) {
    if (failure_reason == -ERR_SIGNATURE_NO_MATCH) {
      // we looked up a secret but it didn't generate the same signature as
      // the client. since we found this access key in keystone, we should
      // reject the request instead of trying other engines
      return result_t::reject(failure_reason);
    }
    return result_t::deny(failure_reason);
  }

  /* Verify expiration. */
  if (t->expired()) {
    ldpp_dout(dpp, 0) << "got expired token: " << t->get_project_name()
                  << ":" << t->get_user_name()
                  << " expired: " << t->get_expires() << dendl;
    return result_t::deny();
  }

  /* check if we have a valid role */
  bool found = false;
  for (const auto& role : accepted_roles.plain) {
    if (t->has_role(role) == true) {
      found = true;
      break;
    }
  }

  if (! found) {
    ldpp_dout(dpp, 5) << "s3 keystone: user does not hold a matching role;"
                     " required roles: "
                  << cct->_conf->rgw_keystone_accepted_roles << dendl;
    return result_t::deny();
  } else {
    /* everything seems fine, continue with this user */
    ldpp_dout(dpp, 5) << "s3 keystone: validated token: " << t->get_project_name()
                  << ":" << t->get_user_name()
                  << " expires: " << t->get_expires() << dendl;

    auto apl = apl_factory->create_apl_remote(cct, s, get_acl_strategy(*t),
                                              get_creds_info(*t, accepted_roles.admin, std::string(access_key_id)));
    return result_t::grant(std::move(apl), completer_factory(secret_key));
  }
}

static void count(const int counter)
{
  if (perfcounter) {
    perfcounter->inc(counter);
  }
}

SecretCache::SecretCache(CephContext* const cct)
  : cct(cct),
    lock(),
    max(cct->_conf->rgw_keystone_token_cache_size),
    s3_token_expiry_length(cct->_conf->rgw_keystone_token_cache_ttl, 0) {
}

void SecretCache::erase_locked(std::map<std::string, secret_entry>::iterator iter)
{
  secrets_lru.erase(iter->second.lru_iter);
  secrets.erase(iter);
}

uint32_t SecretCache::refresh_before_secs() const
{
  const uint64_t configured = cct->_conf->rgw_keystone_token_cache_refresh_before;
  const uint64_t clamped = std::min<uint64_t>(configured,
                                              s3_token_expiry_length.sec() / 2);
  return std::max<uint64_t>(clamped, 1);  // also the background call timeout
}

utime_t SecretCache::jitter() const
{
  const uint64_t max_jitter = std::min<uint64_t>(
      cct->_conf->rgw_keystone_token_cache_ttl_jitter,
      s3_token_expiry_length.sec() / 2);
  if (max_jitter == 0) {
    return utime_t();
  }
  return utime_t(ceph::util::generate_random_number<uint64_t>(0, max_jitter), 0);
}

SecretCache::lookup_result SecretCache::lookup(const std::string& access_key_id,
                                               const bool want_refresh)
{
  lookup_result result;
  const utime_t now = now_fn();
  std::lock_guard<std::mutex> l(lock);

  auto iter = secrets.find(access_key_id);
  if (iter == secrets.end()) {
    return result;
  }

  secret_entry& entry = iter->second;
  if (entry.token.expired() || now > entry.expires) {
    erase_locked(iter);
    return result;
  }

  secrets_lru.erase(entry.lru_iter);
  secrets_lru.push_front(access_key_id);
  entry.lru_iter = secrets_lru.begin();

  result.found = true;
  result.token = entry.token;
  result.secret = entry.secret;
  result.gen = entry.gen;

  if (want_refresh && !entry.refresh_started) {
    /* the entry dies at the earlier of the cache ttl and the token expiry */
    const time_t dies = std::min<time_t>(entry.expires.sec(),
                                         entry.token.get_expires());
    const time_t remaining = dies - static_cast<time_t>(now.sec());
    result.near_expiry = remaining <= static_cast<time_t>(refresh_before_secs());
  }
  return result;
}

bool SecretCache::erase_if_gen(const std::string& access_key_id,
                               const uint64_t gen)
{
  std::lock_guard<std::mutex> l(lock);
  auto iter = secrets.find(access_key_id);
  if (iter == secrets.end() || iter->second.gen != gen) {
    return false;
  }
  erase_locked(iter);
  return true;
}

bool SecretCache::find(const std::string& token_id,
                       SecretCache::token_envelope_t& token,
		       std::string &secret)
{
  lookup_result result = lookup(token_id, false);
  if (!result.found) {
    return false;
  }
  token = std::move(result.token);
  secret = std::move(result.secret);
  return true;
}

utime_t SecretCache::new_expiry() const
{
  /* shortened by a random jitter so that entries cached together do not
   * expire together; never lengthened, the ttl stays a hard bound */
  return now_fn() + s3_token_expiry_length - jitter();
}

void SecretCache::add(const std::string& token_id,
                      const SecretCache::token_envelope_t& token,
		      const std::string& secret)
{
  const utime_t expires = new_expiry();
  std::lock_guard<std::mutex> l(lock);
  add_locked(token_id, token, secret, expires);
}

bool SecretCache::add_unless_replaced(const std::string& token_id,
                                      const token_envelope_t& token,
                                      const std::string& secret,
                                      const uint64_t gen)
{
  const utime_t expires = new_expiry();
  std::lock_guard<std::mutex> l(lock);
  auto iter = secrets.find(token_id);
  if (iter != secrets.end() && iter->second.gen != gen) {
    return false;
  }
  add_locked(token_id, token, secret, expires);
  return true;
}

void SecretCache::add_locked(const std::string& token_id,
                             const token_envelope_t& token,
                             const std::string& secret,
                             const utime_t expires)
{
  map<string, secret_entry>::iterator iter = secrets.find(token_id);
  if (iter != secrets.end()) {
    secret_entry& e = iter->second;
    secrets_lru.erase(e.lru_iter);
  }

  secrets_lru.push_front(token_id);
  secret_entry& entry = secrets[token_id];
  entry.token = token;
  entry.secret = secret;
  entry.expires = expires;
  entry.lru_iter = secrets_lru.begin();
  entry.gen = ++next_gen;
  entry.refresh_started = false;

  while (secrets_lru.size() > max) {
    list<string>::reverse_iterator riter = secrets_lru.rbegin();
    iter = secrets.find(*riter);
    assert(iter != secrets.end());
    secrets.erase(iter);
    secrets_lru.pop_back();
  }
}

size_t SecretCache::size()
{
  std::lock_guard<std::mutex> l(lock);
  return secrets.size();
}

size_t SecretCache::inflight_size()
{
  std::lock_guard<std::mutex> l(lock);
  return inflight.size();
}

uint32_t SecretCache::refreshes_in_flight()
{
  std::lock_guard<std::mutex> l(lock);
  return refreshing;
}

SecretCache::join_result
SecretCache::join_or_create_flight(const std::string& access_key_id,
                                   const uint64_t seen_gen)
{
  join_result result;
  const utime_t now = now_fn();
  std::lock_guard<std::mutex> l(lock);

  if (auto iter = secrets.find(access_key_id); iter != secrets.end()) {
    const secret_entry& entry = iter->second;
    if (entry.gen != seen_gen &&
        !entry.token.expired() && now <= entry.expires) {
      result.late_hit = true;
      return result;
    }
  }

  if (auto iter = inflight.find(access_key_id); iter != inflight.end()) {
    result.flight = iter->second;
  } else {
    result.flight = std::make_shared<Flight>();
    inflight.emplace(access_key_id, result.flight);
  }
  return result;
}

void SecretCache::remove_flight_if(const std::string& access_key_id,
                                   const flight_ptr& flight)
{
  std::lock_guard<std::mutex> l(lock);
  auto iter = inflight.find(access_key_id);
  if (iter != inflight.end() && iter->second == flight) {
    inflight.erase(iter);
  }
}

SecretCache::Outcome SecretCache::classify(const FetchResult& r) noexcept
{
  if (r.thrown || r.eptr) {
    return Outcome::error;
  }
  if (r.token && r.secret) {
    return Outcome::success;
  }
  if (r.token) {
    return Outcome::token_without_secret;
  }
  if (r.failure_reason == -ERR_INVALID_ACCESS_KEY) {
    return Outcome::invalid_key;
  }
  if (r.failure_reason == -ERR_SIGNATURE_NO_MATCH) {
    return Outcome::sig_mismatch;
  }
  return Outcome::error;
}

FetchResult SecretCache::run_fetch(const DoutPrefixProvider* dpp,
                                   const SignedSample& sample,
                                   const fetch_fn& fetch,
                                   optional_yield y,
                                   const long timeout_secs)
{
  FetchResult r;
  try {
    r = fetch(dpp, sample, y, timeout_secs);
  } catch (const int err) {
    r.thrown = err;
  } catch (const boost::context::detail::forced_unwind&) {
    throw;  // a suspended coroutine is being destroyed: let it unwind
  } catch (...) {
    r.eptr = std::current_exception();
  }
  return r;
}

FetchResult SecretCache::fetch_and_add(const DoutPrefixProvider* dpp,
                                       const SignedSample& sample,
                                       const fetch_fn& fetch,
                                       optional_yield y,
                                       const long timeout_secs)
{
  FetchResult r = run_fetch(dpp, sample, fetch, y, timeout_secs);
  if (r.token && r.secret) {
    /* Add token, secret pair to cache, and set timeout */
    add(sample.access_key_id, *r.token, *r.secret);
  }
  return r;
}

SecretCache::access_result SecretCache::to_access_result(FetchResult&& r)
{
  if (r.eptr) {
    std::rethrow_exception(r.eptr);
  }
  if (r.thrown) {
    throw *r.thrown;
  }
  return {std::move(r.token), std::move(r.secret), r.failure_reason};
}

std::optional<SecretCache::access_result>
SecretCache::serve_cached(const DoutPrefixProvider* dpp,
                          const SignedSample& sample,
                          const lookup_result& cached,
                          verify_fn verify,
                          const bool ignore_signature,
                          const fetch_fn& fetch,
                          optional_yield y)
{
  /* Check that credentials can correctly be used to sign data */
  if (cached.found) {
    /* We should ignore checking signature in cache if caller tells us to
     * which means we're handling a HTTP OPTIONS call. */
    if (ignore_signature) {
      ldpp_dout(dpp, 20) << "ignore_signature set and found in cache" << dendl;
      count(l_rgw_keystone_secret_cache_hit);
      return access_result{cached.token, cached.secret, 0};
    }
    if (verify(cached.secret)) {
      count(l_rgw_keystone_secret_cache_hit);
      if (cached.near_expiry) {
        maybe_spawn_refresh(dpp, sample, cached.gen, fetch, y);
      }
      return access_result{cached.token, cached.secret, 0};
    }
    ldpp_dout(dpp, 0) << "Secret string does not correctly sign payload, cache miss" << dendl;
  } else {
    ldpp_dout(dpp, 0) << "No stored secret string, cache miss" << dendl;
  }
  count(l_rgw_keystone_secret_cache_miss);
  return std::nullopt;
}

std::optional<SecretCache::access_result>
SecretCache::use_shared_result(const DoutPrefixProvider* dpp,
                               FetchResult&& r,
                               verify_fn verify)
{
  count(l_rgw_keystone_secret_cache_coalesced);
  switch (classify(r)) {
    case Outcome::success:
      /* Keystone validated the leader's signature, not ours */
      if (verify(*r.secret)) {
        return access_result{std::move(r.token), std::move(r.secret), 0};
      }
      /* as with a mismatching cache hit, let Keystone judge our sample */
      ldpp_dout(dpp, 20) << "signature does not match the secret fetched by "
                            "a concurrent request, retrying" << dendl;
      return std::nullopt;
    case Outcome::invalid_key:
    case Outcome::error:
      /* a verdict about the key, or an error every request would have hit */
      return to_access_result(std::move(r));
    case Outcome::sig_mismatch:
    case Outcome::token_without_secret:
      /* Keystone rejected the leader's sample; ours may still be fine, and
       * without a secret we cannot tell locally */
      ldpp_dout(dpp, 20) << "concurrent keystone lookup not usable for this "
                            "request, retrying" << dendl;
      return std::nullopt;
  }
  return std::nullopt;
}

SecretCache::access_result
SecretCache::get_or_fetch(const DoutPrefixProvider* dpp,
                          const SignedSample& sample,
                          verify_fn verify,
                          const bool ignore_signature,
                          const fetch_fn& fetch,
                          optional_yield y)
{
  const bool coalesce = cct->_conf->rgw_keystone_token_cache_coalesce_misses;
  /* an OPTIONS request carries no signature Keystone could re-validate */
  const bool want_refresh = !ignore_signature &&
      cct->_conf->rgw_keystone_token_cache_refresh_enabled;

  for (int rounds_waited = 0;;) {
    /* Get a token from the cache if one has already been stored */
    const lookup_result cached = lookup(sample.access_key_id, want_refresh);
    if (auto served = serve_cached(dpp, sample, cached, verify,
                                   ignore_signature, fetch, y)) {
      return std::move(*served);
    }

    /* No cached token, token expired, or secret invalid: fall back to
     * keystone. An OPTIONS request (no signature to verify a shared
     * result with) and a request that has waited twice go on their own. */
    if (!coalesce || ignore_signature || rounds_waited >= max_coalesce_rounds) {
      return to_access_result(fetch_and_add(dpp, sample, fetch, y, 0));
    }

    /* Share the round trip with other requests that miss this key right
     * now. A late hit counts as a round: a signature that keeps failing
     * against secrets others fetch must not loop here for ever. */
    const uint64_t seen_gen = cached.found ? cached.gen : 0;
    const join_result joined = join_or_create_flight(sample.access_key_id,
                                                     seen_gen);
    if (joined.late_hit) {
      ++rounds_waited;
      continue;
    }

    const FlightGuard guard{*this, sample.access_key_id, joined.flight};
    bool leader = false;
    FetchResult r = call_once(joined.flight->once, y, [&] {
        leader = true;
        return fetch_and_add(dpp, sample, fetch, y, 0);
      });

    if (leader) {
      /* Keystone judged this very sample */
      return to_access_result(std::move(r));
    }
    if (auto shared = use_shared_result(dpp, std::move(r), verify)) {
      return std::move(*shared);
    }
    ++rounds_waited;
  }
}


void SecretCache::maybe_spawn_refresh(const DoutPrefixProvider* dpp,
                                      const SignedSample& sample,
                                      const uint64_t gen,
                                      const fetch_fn& fetch,
                                      optional_yield y)
{
  if (!y) {
    /* no executor to run a coroutine on: give this entry up, once */
    mark_refresh_started(sample.access_key_id, gen);
    ldpp_dout(dpp, 20) << "keystone secret cache: no yield context, not "
                          "refreshing " << sample.access_key_id << dendl;
    count(l_rgw_keystone_secret_cache_refresh_skipped);
    return;
  }
  if (!arm_refresh(sample.access_key_id, gen)) {
    return;  // another hit was first, or too many refreshes are running
  }
  count(l_rgw_keystone_secret_cache_refresh);
  try {
    spawn_refresh(sample, gen, fetch, y);
  } catch (const std::exception& e) {
    /* no memory or address space for the coroutine; the request that
     * asked is authenticated and must not suffer for it */
    ldpp_dout(dpp, 1) << "keystone secret cache: cannot start a refresh for "
                      << sample.access_key_id << ": " << e.what() << dendl;
    release_refresh_slot();
    count(l_rgw_keystone_secret_cache_refresh_failed);
    return;
  }
  ldpp_dout(dpp, 10) << "keystone secret cache: refreshing "
                     << sample.access_key_id << " before it expires" << dendl;
}

bool SecretCache::arm_refresh(const std::string& access_key_id,
                              const uint64_t gen)
{
  const uint64_t max_concurrent =
      cct->_conf->rgw_keystone_token_cache_refresh_max_concurrent;
  std::lock_guard<std::mutex> l(lock);

  auto iter = secrets.find(access_key_id);
  if (iter == secrets.end() || iter->second.gen != gen ||
      iter->second.refresh_started) {
    return false;  // gone, replaced, or another hit got here first
  }
  if (refreshing >= max_concurrent) {
    count(l_rgw_keystone_secret_cache_refresh_skipped);
    return false;  // stays armable: a later hit retries once a slot is free
  }
  iter->second.refresh_started = true;
  ++refreshing;
  return true;
}

void SecretCache::mark_refresh_started(const std::string& access_key_id,
                                       const uint64_t gen)
{
  std::lock_guard<std::mutex> l(lock);
  auto iter = secrets.find(access_key_id);
  if (iter != secrets.end() && iter->second.gen == gen) {
    iter->second.refresh_started = true;
  }
}

void SecretCache::release_refresh_slot()
{
  std::lock_guard<std::mutex> l(lock);
  ceph_assert(refreshing > 0);
  --refreshing;
}

void SecretCache::spawn_refresh(const SignedSample& sample,
                                const uint64_t gen,
                                const fetch_fn& fetch,
                                optional_yield y)
{
  /* The request, its dpp and its strings are gone by the time Keystone
   * answers: the job owns copies of everything it needs. `this` is the
   * process-lifetime singleton (or a test instance that outlives its
   * io_context). The coroutine is work on the frontend's io_context, so
   * shutdown drains it like an in-flight request. */
  boost::asio::spawn(y.get_yield_context().get_executor(),
      std::allocator_arg, boost::context::protected_fixedsize_stack{512 * 1024},
      [this, sample, gen, fetch] (boost::asio::yield_context yield) {
        run_refresh(sample, gen, fetch, optional_yield{yield});
      },
      [cct = cct] (std::exception_ptr eptr) {
        if (eptr) {
          ldout(cct.get(), 1) << "keystone secret cache: refresh job "
                                 "terminated by an exception" << dendl;
        }
      });
}

SecretCache::flight_ptr
SecretCache::create_refresh_flight(const std::string& access_key_id)
{
  std::lock_guard<std::mutex> l(lock);
  if (inflight.count(access_key_id)) {
    return nullptr;
  }
  auto flight = std::make_shared<Flight>();
  inflight.emplace(access_key_id, flight);
  return flight;
}

void SecretCache::run_refresh(const SignedSample& sample,
                              const uint64_t gen,
                              const fetch_fn& fetch,
                              optional_yield y)
{
  struct SlotGuard {
    SecretCache& cache;
    ~SlotGuard() { cache.release_refresh_slot(); }
  } slot{*this};

  const std::string prefix =
      "keystone secret cache refresh " + sample.access_key_id + ": ";
  const DoutPrefix dpp(cct.get(), dout_subsys, prefix.c_str());
  try {
    const flight_ptr flight = create_refresh_flight(sample.access_key_id);
    if (!flight) {
      ldpp_dout(&dpp, 20) << "a request is validating this key right now, "
                             "skipping" << dendl;
      count(l_rgw_keystone_secret_cache_refresh_skipped);
      return;
    }
    const FlightGuard guard{*this, sample.access_key_id, flight};

    bool leader = false;
    bool cached = false;
    const FetchResult r = call_once(flight->once, y, [&] {
        leader = true;
        FetchResult fetched = run_fetch(&dpp, sample, fetch, y,
                                        refresh_before_secs());
        if (fetched.token && fetched.secret) {
          cached = add_unless_replaced(sample.access_key_id, *fetched.token,
                                       *fetched.secret, gen);
        }
        return fetched;
      });

    if (!leader) {
      /* a request slipped in first and Keystone judged its sample, not ours */
      ldpp_dout(&dpp, 20) << "a request validated this key in the meantime, "
                             "skipping" << dendl;
      count(l_rgw_keystone_secret_cache_refresh_skipped);
      return;
    }
    finish_refresh(&dpp, sample.access_key_id, gen, r, cached);
  } catch (const boost::context::detail::forced_unwind&) {
    throw;  // the coroutine is being destroyed: let it unwind
  } catch (const std::exception& e) {
    ldpp_dout(&dpp, 1) << "unexpected exception: " << e.what() << dendl;
    count(l_rgw_keystone_secret_cache_refresh_failed);
  } catch (...) {
    ldpp_dout(&dpp, 1) << "unexpected exception" << dendl;
    count(l_rgw_keystone_secret_cache_refresh_failed);
  }
}

static std::string describe(const FetchResult& r)
{
  if (r.eptr) {
    return "an exception";
  }
  if (r.thrown) {
    return "error " + std::to_string(*r.thrown);
  }
  return "keystone reply " + std::to_string(r.failure_reason);
}

void SecretCache::finish_refresh(const DoutPrefixProvider* dpp,
                                 const std::string& access_key_id,
                                 const uint64_t gen,
                                 const FetchResult& r,
                                 const bool cached)
{
  const Outcome outcome = classify(r);
  if (outcome == Outcome::success) {
    if (cached) {
      ldpp_dout(dpp, 10) << "refreshed" << dendl;
      count(l_rgw_keystone_secret_cache_refresh_ok);
    } else {
      ldpp_dout(dpp, 20) << "a newer credential was cached in the meantime, "
                            "dropping ours" << dendl;
      count(l_rgw_keystone_secret_cache_refresh_skipped);
    }
    return;
  }

  const bool deleted = outcome == Outcome::invalid_key ||
      (outcome == Outcome::token_without_secret &&
       r.failure_reason == -ERR_INVALID_ACCESS_KEY);
  if (!deleted) {
    /* A 401 cannot be told apart from a stale admin token, so it does not
     * evict either: the credential is served until it expires, as today. */
    ldpp_dout(dpp, 5) << "failed with " << describe(r)
                      << ", keeping the cached credential until it expires"
                      << dendl;
    count(l_rgw_keystone_secret_cache_refresh_failed);
    return;
  }

  /* The credential no longer exists in Keystone: stop serving it, unless
   * a newer one has been cached in the meantime. */
  if (erase_if_gen(access_key_id, gen)) {
    ldpp_dout(dpp, 5) << "credential no longer exists in keystone, evicted it"
                      << dendl;
    count(l_rgw_keystone_secret_cache_refresh_evicted);
  } else {
    ldpp_dout(dpp, 20) << "credential no longer exists in keystone but was "
                          "replaced in the meantime" << dendl;
    count(l_rgw_keystone_secret_cache_refresh_skipped);
  }
}

}; /* namespace keystone */
}; /* namespace auth */
}; /* namespace rgw */
