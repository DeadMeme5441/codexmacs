;;; codex-auth.el --- Authenticate with OpenAI for Codex -*- lexical-binding: t; -*-
;;
;; Copyright (C) 2025 DeadMeme5441
;;
;; Author: DeadMeme5441 <hrishikesh290@gmail.com>
;; Maintainer: DeadMeme5441 <hrishikesh290@gmail.com>
;; Created: September 26, 2025
;; Modified: September 26, 2025
;; Version: 1.0.0
;; Keywords: codex cli gpt ai authentication
;; Homepage: https://github.com/DeadMeme5441/codexmacs
;; Package-Requires: ((emacs "25.1") (request "0.3.0") (simple-httpd "1.5.1"))
;;
;; This file is not part of GNU Emacs.
;;
;;; Commentary:
;;
;; This library provides functions to authenticate with the OpenAI API
;; using the same OAuth 2.0 PKCE flow as the official codex-rs CLI.
;; It starts a local server to handle the redirect, opens a browser
;; for user login, exchanges the authorization code for tokens, and
;; securely stores the final credentials in `~/.codex/auth.json`.
;;
;; To use, simply call the interactive function `codex-auth-login`.
;;
;;; Code:

(require 'cl-lib)
(require 'url)
(require 'simple-httpd)
(require 'request)
(require 'json)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Constants and State Variables
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defconst codexmacs--ISSUER "https://auth.openai.com"
  "The base URL for the OpenAI authentication server.")

(defconst codexmacs--CLIENT-ID "app_EMoamEEZ73f0CkXaXp7hrann"
  "The official OAuth2 client ID for the Codex CLI application.")

(defconst codexmacs--PORT 1455
  "The default local port for the temporary redirect server.")

(defvar codexmacs--login-pkce-codes nil
  "A global variable to hold the PKCE codes for the current login attempt.
This is necessary so the HTTPD servlet can access the verifier.")

(defvar codexmacs--login-state nil
  "A global variable to hold the random state string for CSRF protection.")

(defvar codexmacs--login-finished-p nil
  "A flag used to signal the waiting loop that the login process is complete.")

(defvar codexmacs--login-redirect-uri nil
  "Stores the redirect URI used for the current OAuth session.")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Utility helpers
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun codexmacs--json-get (object key)
  "Fetch KEY from JSON OBJECT regardless of symbol/string key types."
  (cond
   ((hash-table-p object)
    (or (gethash key object)
        (and (stringp key) (gethash (intern key) object))
        (and (symbolp key) (gethash (symbol-name key) object))))
   ((listp object)
    (or (alist-get key object nil nil #'equal)
        (and (stringp key)
             (alist-get (intern key) object nil nil #'eq))
        (and (symbolp key)
             (alist-get (symbol-name key) object nil nil #'string=))))))

(defun codexmacs--parse-json ()
  "Parse the current buffer as JSON with string keys."
  (let ((json-object-type 'alist)
        (json-array-type 'list)
        (json-key-type 'string))
    (json-read)))

(defun codexmacs--base64url-decode (payload)
  "Decode Base64URL PAYLOAD into a raw string, or nil on failure."
  (when payload
    (let* ((standard (replace-regexp-in-string
                      "_" "/"
                      (replace-regexp-in-string "-" "+" payload)))
           (padding (mod (- 4 (mod (length standard) 4)) 4))
           (padded (concat standard (make-string padding ?=))))
      (condition-case nil
          (base64-decode-string padded)
        (error nil)))))

(defun codexmacs--jwt-claims (jwt)
  "Extract the `https://api.openai.com/auth` claims from JWT payload.
Returns an alist keyed by strings."
  (when (and jwt (string-match-p "\\." jwt))
    (pcase (split-string jwt "\." t)
      (`(,header ,payload ,signature)
       (ignore header signature)
       (let ((decoded (codexmacs--base64url-decode payload)))
         (when decoded
           (let ((json-object-type 'alist)
                 (json-array-type 'list)
                 (json-key-type 'string)
                 (parsed (json-read-from-string decoded)))
             (or (codexmacs--json-get parsed "https://api.openai.com/auth")
                 parsed))))))))

(defun codexmacs--format-query-string (params)
  "Turn PARAMS alist into a URL-encoded query string."
  (mapconcat
   (lambda (pair)
     (format "%s=%s" (car pair) (url-hexify-string (cdr pair))))
   params
   "&"))

(defun codexmacs--platform-url ()
  "Return the platform URL corresponding to the configured issuer."
  (if (string= codexmacs--ISSUER "https://auth.openai.com")
      "https://platform.openai.com"
    "https://platform.api.openai.org"))

(defun codexmacs--redirect-and-finish (path)
  "Redirect the browser to PATH and conclude the login flow."
  (httpd-redirect t path 302)
  (setq codexmacs--login-finished-p t)
  ;; Stop the temporary server shortly after so the waiting loop exits even
  ;; if the browser window is closed before hitting /success.
  (run-at-time
   1 nil
   (lambda ()
     (ignore-errors
       (httpd-stop)))))

(defun codexmacs--build-success-url (token-record access-claims org-id project-id &optional exchanged-access-token)
  "Compose the success redirect URL mirroring codex CLI behaviour."
  (let* ((id-token (codexmacs--json-get token-record "id_token"))
         (access-token (codexmacs--json-get token-record "access_token"))
         (refresh-token (codexmacs--json-get token-record "refresh_token"))
         (plan-type (or (codexmacs--json-get access-claims "chatgpt_plan_type") ""))
         (platform-url (codexmacs--platform-url))
         (query (if (and org-id project-id exchanged-access-token)
                    `(("id_token" . ,(or id-token ""))
                      ("access_token" . ,(or access-token ""))
                      ("refresh_token" . ,(or refresh-token ""))
                      ("exchanged_access_token" . ,(or exchanged-access-token ""))
                      ("org_id" . ,org-id)
                      ("project_id" . ,project-id)
                      ("plan_type" . ,plan-type)
                      ("platform_url" . ,platform-url))
                  `(("id_token" . ,(or id-token ""))
                    ("needs_setup" . "false")
                    ("org_id" . ,(or org-id ""))
                    ("project_id" . ,(or project-id ""))
                    ("plan_type" . ,plan-type)
                    ("platform_url" . ,platform-url)))))
    (format "/success?%s" (codexmacs--format-query-string query))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; PKCE (Proof Key for Code Exchange) Generation
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(cl-defstruct pkce-codes
  "Holds the PKCE verifier and challenge strings."
  code-verifier
  code-challenge)

(defun codexmacs--generate-pkce-verifier ()
  "Generate a URL-safe, unpadded base64 string from 64 random bytes."
  (let ((random-string (make-string 64 0)))
    (dotimes (i 64)
      (aset random-string i (random 256)))
    (base64url-encode-string random-string t)))

(defun codexmacs--generate-pkce-challenge (code-verifier)
  "Generate the PKCE challenge as a SHA256 hash of the verifier."
  ;; The PKCE spec requires base64url(SHA256(code_verifier)).
  ;; `secure-hash' must return the raw bytes of the digest, otherwise we
  ;; would end up hashing the hexadecimal string representation which
  ;; breaks the verifier/challenge pairing.
  (base64url-encode-string (secure-hash 'sha256 code-verifier nil nil t) t))

(defun codexmacs--generate-pkce-codes ()
  "Generates and returns a `pkce-codes` struct."
  (let* ((verifier (codexmacs--generate-pkce-verifier))
         (challenge (codexmacs--generate-pkce-challenge verifier)))
    (make-pkce-codes :code-verifier verifier
                     :code-challenge challenge)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; State and URL Generation
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun codexmacs--generate-state ()
  "Generate a random state string from 32 random bytes for CSRF protection."
  (let ((random-string (make-string 32 0)))
    (dotimes (i 32)
      (aset random-string i (random 256)))
    (base64url-encode-string random-string t)))

(defun codexmacs--build-authorize-url (redirect-uri pkce-codes state)
  "Generates the full authorization URL to which the user will be sent."
  (let* ((params (list
                  (cons "response_type" "code")
                  (cons "client_id" codexmacs--CLIENT-ID)
                  (cons "redirect_uri" redirect-uri)
                  (cons "scope" "openid profile email offline_access")
                  (cons "code_challenge" (pkce-codes-code-challenge pkce-codes))
                  (cons "code_challenge_method" "S256")
                  (cons "id_token_add_organizations" "true")
                  (cons "codex_cli_simplified_flow" "true")
                  (cons "state" state)
                  (cons "originator" "codex_cli_rs")))
         (query-string (mapconcat (lambda (pair)
                                    (format "%s=%s"
                                            (car pair)
                                            (url-hexify-string (cdr pair))))
                                  params
                                  "&")))
    (concat codexmacs--ISSUER "/oauth/authorize?" query-string)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Token Exchange and Persistence
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun codexmacs--persist-tokens (token-data api-key)
  "Saves the token data and API key to `~/.codex/auth.json`."
  (let* ((codex-home (expand-file-name "~/.codex/"))
         (auth-file (expand-file-name "auth.json" codex-home))
         (timestamp (format-time-string "%Y-%m-%dT%H:%M:%SZ" (current-time) t))
         (auth-data `(("OPENAI_API_KEY" . ,api-key)
                      ("tokens" . ,token-data)
                      ("last_refresh" . ,timestamp))))

    (unless (file-directory-p codex-home)
      (make-directory codex-home t))

    (with-temp-file auth-file
      (insert (json-encode auth-data)))))

(defun codexmacs--obtain-api-key (id-token success-callback &optional proc)
  "Exchanges the ID token for a final OpenAI API key."
  (let* ((proc (or proc httpd-current-proc))
         (today (format-time-string "%Y-%m-%d" (current-time) t))
         (params (list
                  (cons "grant_type" "urn:ietf:params:oauth:grant-type:token-exchange")
                  (cons "client_id" codexmacs--CLIENT-ID)
                  (cons "requested_token" "openai-api-key")
                  (cons "subject_token" id-token)
                  (cons "subject_token_type" "urn:ietf:params:oauth:token-type:id_token")
                  (cons "name" (format "ChatGPT Local [auto-generated] (%s)" today))))
         (body-string (mapconcat (lambda (pair)
                                   (format "%s=%s"
                                           (car pair)
                                           (url-hexify-string (cdr pair))))
                                 params
                                 "&")))
    (request
      (concat codexmacs--ISSUER "/oauth/token")
      :type "POST"
      :headers '(("Content-Type" . "application/x-www-form-urlencoded"))
      :data body-string
      :parser #'codexmacs--parse-json
      :success (cl-function
                (lambda (&key data &allow-other-keys)
                  (let ((httpd-current-proc proc))
                    (message "Successfully obtained API key.")
                    (funcall success-callback data))))
      :error (cl-function
              (lambda (&key error-thrown response &allow-other-keys)
                (let ((httpd-current-proc proc))
                  (message "Error obtaining API key: %S (status %s)"
                           error-thrown
                           (and response (request-response-status-code response)))
                  (when response
                    (message "API key response body: %S"
                             (request-response-data response)))
                  (setq codexmacs--login-finished-p t)
                  (httpd-error t 500 "Failed to obtain API key")
                  (httpd-stop)))))))

(defun codexmacs--exchange-code-for-tokens (redirect-uri pkce-codes code success-callback &optional proc)
  "Exchange an authorization code for access/refresh/id tokens."
  (let* ((proc (or proc httpd-current-proc))
         (params (list
                  (cons "grant_type" "authorization_code")
                  (cons "code" code)
                  (cons "redirect_uri" redirect-uri)
                  (cons "client_id" codexmacs--CLIENT-ID)
                  (cons "code_verifier" (pkce-codes-code-verifier pkce-codes))))
         (body-string (mapconcat (lambda (pair)
                                   (format "%s=%s"
                                           (car pair)
                                           (url-hexify-string (cdr pair))))
                                 params
                                 "&")))
    (request
      (concat codexmacs--ISSUER "/oauth/token")
      :type "POST"
      :headers '(("Content-Type" . "application/x-www-form-urlencoded"))
      :data body-string
      :parser #'codexmacs--parse-json
      :success (cl-function
                (lambda (&key data &allow-other-keys)
                  (let ((httpd-current-proc proc))
                    (message "Successfully exchanged code for tokens.")
                    (funcall success-callback data))))
      :error (cl-function
              (lambda (&key error-thrown &allow-other-keys)
                (let ((httpd-current-proc proc))
                  (message "Error exchanging code for tokens: %S" error-thrown)
                  (setq codexmacs--login-finished-p t)
                  (httpd-error t 500 "Failed to exchange code for tokens")
                  (httpd-stop)))))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; HTTP Server and Main Entry Point
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defservlet* auth/callback "text/html" (code scope state)
  "HTTPD servlet to handle the OAuth redirect from OpenAI.
This function orchestrates the chain of asynchronous token exchanges and
then redirects the browser to the final /success page."
  (cl-block codexmacs-callback
    (let ((proc httpd-current-proc))
      (message "Callback received. Code: %s, Scope: %s, State: %s" code scope state)

      ;; 1. Security Check: Ensure the state matches what we sent.
      (unless (and state codexmacs--login-state
                   (string= state codexmacs--login-state))
        (let ((httpd-current-proc proc))
          (message "State mismatch: expected %s got %s"
                   codexmacs--login-state state)
          (httpd-error t 400 "State mismatch: CSRF attempt detected."))
        (cl-return-from codexmacs-callback nil))

      (unless code
        (let ((httpd-current-proc proc))
          (httpd-error t 400 "Missing authorization code"))
        (cl-return-from codexmacs-callback nil))

      ;; 2. Start the asynchronous chain of API calls.
      (codexmacs--exchange-code-for-tokens
       codexmacs--login-redirect-uri
       codexmacs--login-pkce-codes
       code
       (lambda (token-data)
         (let ((httpd-current-proc proc))
           (message "Token received: %S" token-data)
           (let ((id-token (codexmacs--json-get token-data "id_token"))
                 (access-token (codexmacs--json-get token-data "access_token"))
                 (refresh-token (codexmacs--json-get token-data "refresh_token")))
             (cl-block token-step
               (cond
                ((not id-token)
                 (httpd-error t 500 "Authorization server response missing id_token")
                 (setq codexmacs--login-finished-p t)
                 (httpd-stop)
                 (cl-return-from token-step nil))
                ((not access-token)
                 (httpd-error t 500 "Authorization server response missing access_token")
                 (setq codexmacs--login-finished-p t)
                 (httpd-stop)
                 (cl-return-from token-step nil))
                ((not refresh-token)
                 (httpd-error t 500 "Authorization server response missing refresh_token")
                 (setq codexmacs--login-finished-p t)
                 (httpd-stop)
                 (cl-return-from token-step nil))
                (t
                 (let* ((claims (codexmacs--jwt-claims id-token))
                        (access-claims (codexmacs--jwt-claims access-token))
                        (org-id (codexmacs--json-get claims "organization_id"))
                        (project-id (codexmacs--json-get claims "project_id"))
                        (account-id (or (codexmacs--json-get claims "chatgpt_account_id")
                                        (codexmacs--json-get claims "user_id")))
                        (token-record `(("id_token" . ,id-token)
                                        ("access_token" . ,access-token)
                                        ("refresh_token" . ,refresh-token)
                                        ("account_id" . ,account-id))))
                   (if (and org-id project-id)
                       (progn
                         (message "Organization/project detected; requesting API key...")
                         (codexmacs--obtain-api-key
                          id-token
                          (lambda (api-key-data)
                            (let ((httpd-current-proc proc))
                              (let ((api-key (codexmacs--json-get api-key-data "access_token")))
                                (if (not api-key)
                                    (progn
                                      (httpd-error t 500 "Authorization server response missing access_token")
                                      (setq codexmacs--login-finished-p t)
                                      (httpd-stop))
                                  (message "SUCCESS! Got final API Key: %s" api-key)
                                  (codexmacs--persist-tokens token-record api-key)
                                  (message "Login credentials saved.")
                                  (let ((success-url (codexmacs--build-success-url
                                                      token-record access-claims org-id project-id api-key)))
                                    (codexmacs--redirect-and-finish success-url)))))))
                         proc))
                   (progn
                     (message "Skipping API key exchange: missing organization/project assignments.")
                     (codexmacs--persist-tokens token-record nil)
                     (message "Login credentials saved without API key.")
                     (let ((success-url (codexmacs--build-success-url
                                         token-record access-claims org-id project-id)))
                       (codexmacs--redirect-and-finish success-url))
                     proc))))))))))))


(defservlet* success "text/html" ()
  "Displays the final success page to the user in their browser.
Mirrors the Codex CLI by serving the bundled assets/success.html file."
  ;; Signal the main loop to stop waiting and shut down the server.
  (setq codexmacs--login-finished-p t)
  (httpd-stop)
  (message "Login complete. Server stopped.")
  (let* ((base-dir (file-name-directory (or load-file-name buffer-file-name)))
         (success-html (expand-file-name "assets/success.html" base-dir)))
    (if (file-exists-p success-html)
        (insert-file-contents success-html)
      (progn
        (message "Warning: %s not found; falling back to inline success page" success-html)
        (insert "<h1>Login Successful!</h1><p>You can now close this browser tab.</p>")))))

(defservlet* cancel "text/html" ()
  "Handles user cancellation of the login process."
  (message "Login cancelled by user.")
  (setq codexmacs--login-finished-p t)
  (httpd-stop)
  (insert "<h1>Login Cancelled</h1><p>You have cancelled the login process.</p>"))



;;;###autoload
(defun codex-auth-login ()
  "Start the full login flow to authenticate with OpenAI."
  (interactive)
  ;; 1. Reset state variables for a clean login attempt.
  (setq codexmacs--login-pkce-codes (codexmacs--generate-pkce-codes))
  (setq codexmacs--login-state (codexmacs--generate-state))
  (setq codexmacs--login-redirect-uri
        (format "http://localhost:%d/auth/callback" codexmacs--PORT))
  (setq codexmacs--login-finished-p nil)

  ;; 2. Build the URL.
  (let* ((auth-url (codexmacs--build-authorize-url codexmacs--login-redirect-uri
                                                   codexmacs--login-pkce-codes
                                                   codexmacs--login-state)))

    ;; 3. Configure and start the server.
    (setq httpd-port codexmacs--PORT)
    (setq httpd-host "localhost")
    (message "Starting temporary login server on port %d..." httpd-port)
    (httpd-start)

    (message "Opening authentication URL in your browser...")
    (browse-url auth-url)

    (message "Proceed to authentication on your browser...")

    ;; 4. Wait until one of the servlets signals that it's finished.
    (while (not codexmacs--login-finished-p)
      (sit-for 1.0))

    (message "Login process finished.")))


(provide 'codex-auth)

;;; codex-auth.el ends here
