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
        
        login = function(role, credentials = NULL) {
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
              action = "/")
          
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
