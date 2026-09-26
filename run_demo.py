"""Run the Secure SWE judge-facing demo."""
import os
import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("secure_swe.web.app:app", host="0.0.0.0", port=port, reload=False)
