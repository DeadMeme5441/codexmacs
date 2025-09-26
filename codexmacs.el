;;; codexmacs.el --- Emacs helpers for Codex OAuth -*- lexical-binding: t; -*-
;;
;; Copyright (C) 2025 DeadMeme5441
;;
;; Author: DeadMeme5441 <hrishikesh290@gmail.com>
;; Maintainer: DeadMeme5441 <hrishikesh290@gmail.com>
;; Version: 1.0.0
;; Package-Requires: ((emacs "25.1") (request "0.3.0") (simple-httpd "1.5.1"))
;; Homepage: https://github.com/DeadMeme5441/codexmacs
;; Keywords: codex cli gpt ai authentication
;;
;; This file is not part of GNU Emacs.
;;
;;; Commentary:
;;
;; Thin wrapper around the Codex OAuth implementation.  Provides the
;; interactive entry point `codexmacs-login', which simply delegates to
;; the core routines defined in `codex-auth.el'.
;;
;;; Code:

(require 'codex-auth)

;;;###autoload
(defun codexmacs-login ()
  "Authenticate with OpenAI using the Codex OAuth flow."
  (interactive)
  (codex-auth-login))

;;;###autoload
(defalias 'codexmacs-authenticate #'codexmacs-login)

(provide 'codexmacs)

;;; codexmacs.el ends here
