##' Interact with vault's AWS authentication backend.
##' For more information, please see the vault documentation
##' \url{https://www.vaultproject.io/docs/auth/aws }
##'
##' @template vault_client_auth_userpass
##'
##' @title Vault AWS Authentication Configuration
##' @name vault_client_auth_aws
##'
##' @examples
##' server <- vaultr::vault_test_server(if_disabled = message)
##' if (!is.null(server)) {
##' }
NULL


vault_client_auth_aws <- R6::R6Class(
    "vault_client_auth_aws",
    inherit = vault_client_object,
    cloneable = FALSE,
    
    private = list(
        api_client = NULL,
        mount = NULL
    ),
    
    public = list(
        initialize = function(api_client, mount) {
          super$initialize("Interact and configure vault's AWS support")
          assert_scalar_character(mount)
          private$mount <- sub("^/", "", mount)
          private$api_client <- api_client
        },
        
        custom_mount = function(mount) {
          vault_client_auth_aws$new(private$api_client, mount)
        },
        
        configure_client = function(max_retries = NULL, access_key = NULL,
            secret_key = NULL, iam_endpoint = NULL, sts_endpoint = NULL,
            sts_region = NULL, iam_server_id_header_value = NULL) {
          
          body <- list(
              max_retries = max_retries %&&%
                  assert_scalar_integer(max_retries),
              access_key = access_key %&&%
                  assert_scalar_character(access_key),
              secret_key = secret_key %&&%
                  assert_scalar_character(secret_key),
              iam_endpoint = iam_endpoint %&&%
                  assert_scalar_character(iam_endpoint),
              sts_endpoint = sts_endpoint %&&%
                  assert_scalar_character(sts_endpoint),
              sts_region = sts_region %&&%
                  assert_scalar_character(sts_region),
              iam_server_id_header_value = iam_server_id_header_value %&&%
                  assert_scalar_character(iam_server_id_header_value))
          
          path <- sprintf("/auth/%s/config/client", private$mount)
          private$api_client$POST(path, body = drop_null(body))
          invisible(TRUE)
        },
        
        role_write = function(role,
            bound_iam_principal_arn = NULL,
            token_ttl = NULL,
            token_max_ttl = NULL,
            policies = NULL) {
          
          assert_scalar_character(role, "role")
          
          body <- list(
              role = role,
              auth_type = "iam",
              bound_iam_principal_arn = bound_iam_principal_arn %&&%
                  paste(assert_character(bound_iam_principal_arn),
                      collapse = ","),
              token_ttl = token_ttl %&&%
                  assert_scalar_integer(token_ttl),
              token_max_ttl = token_max_ttl %&&%
                  assert_scalar_integer(token_max_ttl),
              policies = policies %&&%
                  paste(assert_character(policies), collapse = ",")
          )
          
          path <- sprintf("/auth/%s/role/%s", private$mount, role)
          private$api_client$POST(path, body = drop_null(body))
          invisible(NULL)
          
        },
        
        login = function(role, credentials = NULL, region = NULL) {
          assert_scalar_character(role, "role")
          
          if (is.null(credentials)) {
            credentials <- aws.signature::locate_credentials()
          }
          
          d_timestamp <- format(Sys.time(), "%Y%m%dT%H%M%SZ", tz = "UTC")
          sts_canonical_headers <- list(
              "host" = "sts.amazonaws.com",
              "x-amz-date" = d_timestamp)
          
          sts_request_body <- "Action=GetCallerIdentity&Version=2011-06-15"
          
          signature <- aws.signature::signature_v4_auth(
              service = "sts",
              request_body = sts_request_body,
              verb = "POST",
              canonical_headers = sts_canonical_headers,
              action = "/",
              region = region)
          
          vault_request_body <- list(
              role = role,
              iam_http_request_method = "POST",
              iam_request_url = encode64("https://sts.amazonaws.com/"),
              iam_request_body = encode64(sts_request_body),
              iam_request_headers = encode64(
                  jsonlite::toJSON(auto_unbox = TRUE, c(
                      sts_canonical_headers,
                      list(
                          "Accept-Encoding" = "identity",
                          "Content-Length" = "32",
                          "Content-Type" = "application/x-www-form-urlencoded",
                          "Authorization" = signature$SignatureHeader
                      )
                  ))
              )
          )
          
          path <- sprintf("/auth/%s/login", private$mount)
          
          res <- private$api_client$POST(path, body = vault_request_body,
              allow_missing_token = TRUE)
          res$auth
        }
    ))
