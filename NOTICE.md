# Notices and provenance

The Android app in `android/` is derived from Meta's ExecuTorch Android Llama Demo in `meta-pytorch/executorch-examples`, originally located at `llm/android/LlamaDemo`. Its upstream source headers and BSD-style notice are retained. The applicable upstream notice is copied to `LICENSES/EXECUTORCH_LICENSE`. Meta and its contributors do not endorse Don'tClik.

The Android source files were copied from a dirty Meta `executorch-examples` worktree; that upstream commit history is not represented by the file copy. The existing Don'tClik `main` history, including its initial README and MIT license commit, remains intact in this checkout.

The existing root `LICENSE` states MIT for project-owned code. It does not relicense ExecuTorch-derived files, other third-party Android libraries, datasets, model weights, or tokenizers. The previous unverified logo and launcher artwork were excluded. The Home wordmark and text-free launcher symbol were derived from the approved Don'tClik branding supplied for this release. Third-party Android libraries retain their own license terms; inventory licenses before distributing binaries.

Phishing/SMS datasets and derived Android model files were not copied. Their redistribution rights have not been established. Llama weights/tokenizers were not copied. See `docs/DATA_PROVENANCE.md` and `docs/THIRD_PARTY_NOTICES.md`.
