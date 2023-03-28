context("vault: auth: aws")

#      srv_cred <- list(
#          access_key = "VKIAJBRHKH6EVTTNXDHA",
#          secret_key = "vCtSM8ZUEQ3mOFVlYPBQkf2sO6F/W7a5TVzrl3Oj")
#      
#      cl$auth$aws$configure_client(
#          access_key = srv_cred$access_key,
#          secret_key = srv_cred$secret_key)

test_that("login", {
      
      srv <- vault_test_server()
      cl <- srv$client()
      
      cl$auth$enable("aws")
      cl$write("/secret/test", list(a = 1))
      cl$policy$write("standard", 'path "secret/*" {\n  policy = "read"\n}')
      
      # Write Role:
      mock_write_role_vault_request <- function(
          verb, url, verify, token, path, ..., body = NULL, wrap_ttl = NULL,
          to_json = TRUE, allow_missing_token = FALSE) {
        expect_equal(verb, httr::POST)
        expect_is(body, "list")
        expect_equal(body$role, "myrole")
        expect_equal(body$policies, "standard")
        expect_equal(body$bound_iam_principal_arn,
            "arn:aws:iam::123456789012:role/MyRole")
      }
      
      # mockery::stub(cl$auth$aws$role_write, "vaultr::vault_request",
      #     mock_write_role_vault_request, depth = 20)
      with_mock(
          vault_request = mock_write_role_vault_request,
          expect_silent(cl$auth$aws$role_write("myrole", policies = "standard",
                  bound_iam_principal_arn = "arn:aws:iam::123456789012:role/MyRole"))
      )
      
      ## Login:
      cl2 <- srv$client(login = FALSE)
      mock_login_vault_request <- function(
          verb, url, verify, token, path, ..., body = NULL, wrap_ttl = NULL,
          to_json = TRUE, allow_missing_token = FALSE) {
        expect_equal(verb, httr::POST)
        expect_is(body, "list")
        expect_equal(body$role, "myrole")
        expect_true(allow_missing_token)
        expect_equal(body$iam_http_request_method, "POST")
        expect_equal(body$iam_request_url,
            "aHR0cHM6Ly9zdHMuYW1hem9uYXdzLmNvbS8=")
        expect_equal(body$iam_request_body,
            "QWN0aW9uPUdldENhbGxlcklkZW50aXR5JlZlcnNpb249MjAxMS0wNi0xNQ==")
        iam_request_headers <- jsonlite::fromJSON(
            rawToChar(decode64(body$iam_request_headers)))
        list(auth = list(lease_duration = 1, client_token = "doesnotmatter"))
      }
      # mockery::stub(cl2$login, "vault_request",
      #    mock_login_vault_request, depth = 20)
      credentials = list(
          access_key = "VKIAJBRHKH6EVTTNXDHA",
          secret_key = "vCtSM8ZUEQ3mOFVlYPBQkf2sO6F/W7a5TVzrl3Oj")
      with_mock(
          vault_request = mock_login_vault_request,
          expect_silent(cl2$login(method = "aws", role = "myrole",
                  credentials = credentials, quiet = FALSE))
      )
      
      # cl$auth$aws$role_read(role_name)
      # role_id <- cl$auth$approle$role_id_read(role_name)
      # secret <- cl$auth$approle$secret_id_generate(role_name)
      
      ## Login:
      # cl2 <- srv$client(login = FALSE)
      # cl2$login(method = "aws",
      #    role = aws_role)
      # expect_equal(cl2$read("/secret/test"), list(a = 1))
      # expect_error(cl2$write("/secret/test", list(a = 2)))
      
      ## Check our token:
      
      ## Can we read and write where expected:
      
    })

#test_that("custom mount", {
#      srv <- vault_test_server()
#      cl <- srv$client()
#      
#      cl$auth$enable("approle", path = "approle2")
#      ar <- cl$auth$approle$custom_mount("approle2")
#      expect_is(ar, "vault_client_auth_approle")
#      
#      ar$role_write("server")
#      expect_is(ar$role_read("server"), "list")
#      expect_error(cl$auth$approle$role_read("server"))
#    })
