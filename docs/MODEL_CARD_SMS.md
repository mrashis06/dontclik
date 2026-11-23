# SMS model card (experimental)

The classifier was trained on spam/ham message labels. Those labels do not mean verified financial scams. Internal held-out results do not establish representative banking/OTP safety; a separate synthetic diagnostic incorrectly labeled a normal banking alert as spam-like. The Android UI may abstain for banking-related content and unsupported inputs.

Only user-pasted text is analyzed. No inbox permission, automatic blocking, deletion, forwarding, or cloud inference is intended. Non-ASCII text is unsupported by the current model. Do not describe a ham-like classification as a safe message.
