from __future__ import annotations

import json
from pathlib import Path


def main() -> None:
    request = json.loads((Path(__file__).parent / "request.json").read_text(encoding="utf-8"))
    print(json.dumps({"fixture": "harmless-offline-fixture", "received": request["message"]}))


if __name__ == "__main__":
    main()
