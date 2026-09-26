import os

# Unit tests mock network providers and must not read/write the user's
# persistent cache. Production runs keep caching enabled by default.
os.environ["PHISHING_CHECKER_DISABLE_CACHE"] = "1"
