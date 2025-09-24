;;; codexmacs.el --- Description -*- lexical-binding: t; -*-
;;
;; Copyright (C) 2025 DeadMeme5441
;;
;; Author: DeadMeme5441 <hrishikesh290@gmail.com>
;; Maintainer: DeadMeme5441 <hrishikesh290@gmail.com>
;; Created: September 24, 2025
;; Modified: September 24, 2025
;; Version: 0.0.1
;; Keywords: codex cli gpt ai
;; Homepage: https://github.com/DeadMeme5441/codexmacs
;; Package-Requires: ((emacs "24.3"))
;;
;; This file is not part of GNU Emacs.
;;
;;; Commentary:
;;
;;  Description
;;
;;; Code:

(require 'cl-lib)
(require 'url)
(require 'request)

(setq default-issuer "https://auth.openai.com")
(setq default-port 1455)

(cl-defstruct pkceCodes
  "Holds PKCE codes"
  code_verifier
  code_challenge)

(defun generate-pkce-verifier ()
  (let ((random-string (make-string 64 0)))
    (dotimes (i 64)
      (aset random-string i (random 256)))
    (base64url-encode-string random-string t)))

(generate-pkce-verifier)

(defun generate-pkce-challenge (code-verifier)
  (base64url-encode-string (secure-hash 'sha256 code-verifier) t))

(provide 'codexmacs)
;;; codexmacs.el ends here
