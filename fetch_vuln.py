import os
import sys
import json
import time
from datetime import datetime, timezone, timedelta
import requests

# 環境変数から設定を取得
GIST_ID = os.environ.get("GIST_ID", "")
GH_TOKEN = os.environ.get("GH_TOKEN", "")
GIST_FILENAME = "vuln_alert.json"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
VULNRICHMENT_COMMITS_URL = "https://api.github.com/repos/cisagov/vulnrichment/commits?per_page=8"

JST = timezone(timedelta(hours=9))


def get_headers() -> dict:
    headers = {"Accept": "application/vnd.github+json"}
    if GH_TOKEN:
        headers["Authorization"] = f"Bearer {GH_TOKEN}"
    return headers


def fetch_kev_set() -> set:
    """CISA KEVカタログから悪用確認済みCVEのセットを取得"""
    try:
        resp = requests.get(KEV_URL, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return {item.get("cveID") for item in data.get("vulnerabilities", []) if item.get("cveID")}
    except Exception as e:
        print(f"[WARN] Failed to fetch KEV: {e}")
        return set()


def parse_cve5_json(cve_json: dict, kev_set: set) -> dict | None:
    """CVE JSON 5.0 から要件定義の8項目を抽出し、Tier 1〜4のアラート判定を行う"""
    meta = cve_json.get("cveMetadata", {})
    cve_id = meta.get("cveId")
    if not cve_id:
        return None

    containers = cve_json.get("containers", {})
    cna = containers.get("cna", {})
    adp_list = containers.get("adp", [])

    # 1. CVSSスコア抽出 (ADP枠 -> CNA枠の優先順、v3.1 / v4.0 / v3.0 対応)
    cvss_score = 0.0
    for source in [*adp_list, cna]:
        for m in source.get("metrics", []):
            for key in ("cvssV3_1", "cvssV4_0", "cvssV3_0"):
                if key in m and "baseScore" in m[key]:
                    cvss_score = float(m[key]["baseScore"])
                    break
            if cvss_score > 0:
                break
        if cvss_score > 0:
            break

    # 2. 対象製品 (vendor + product)
    product_str = "Unknown Product"
    for source in [cna, *adp_list]:
        affected = source.get("affected", [])
        if affected:
            vendor = affected[0].get("vendor", "")
            prod = affected[0].get("product", "")
            combined = f"{vendor} {prod}".strip()
            if combined and combined.lower() != "n/a":
                product_str = combined[:38]
                break

    # 3. KEV掲載有無 (KEVフィード または CISA ADP内のkevオブジェクト)
    is_kev = cve_id in kev_set
    if not is_kev:
        for adp in adp_list:
            for m in adp.get("metrics", []):
                other = m.get("other", {})
                if other.get("type", "").lower() == "kev":
                    is_kev = True

    # 4. SSVC 3要素 (Exploitation / Automatable / Technical Impact)
    ssvc_exp = "none"
    ssvc_auto = "no"
    ssvc_imp = "partial"

    for adp in adp_list:
        for m in adp.get("metrics", []):
            other = m.get("other", {})
            if other.get("type", "").lower() == "ssvc":
                content = other.get("content", {})
                for opt in content.get("options", []):
                    if "Exploitation" in opt:
                        ssvc_exp = str(opt["Exploitation"]).lower()
                    if "Automatable" in opt:
                        ssvc_auto = str(opt["Automatable"]).lower()
                    if "Technical Impact" in opt:
                        ssvc_imp = str(opt["Technical Impact"]).lower()

    # 5. 脆弱性サマリー (英語Descriptionを1行に整形・最大140文字)
    summary_str = "No summary available."
    for desc in cna.get("descriptions", []):
        if desc.get("lang", "").startswith("en") and desc.get("value"):
            clean = " ".join(desc["value"].replace("\n", " ").replace("\r", " ").split())
            summary_str = clean[:140]
            break

    # 6. 基本設計に基づくアラート発火判定 (Tier 1 〜 Tier 4)
    tier1_kev = is_kev
    tier2_ssvc_act = (ssvc_exp == "active") and (ssvc_auto == "yes" or ssvc_imp == "total")
    tier3_poc_high = (cvss_score >= 8.0) and (ssvc_exp == "poc") and (ssvc_auto == "yes" or ssvc_imp == "total")
    tier4_critical = (cvss_score >= 9.8)

    is_alert = tier1_kev or tier2_ssvc_act or tier3_poc_high or tier4_critical

    # スコアリング（複数候補の中から最も緊急度の高い1件を選ぶための内部優先度）
    priority_score = (
        (1000 if tier1_kev else 0)
        + (500 if tier2_ssvc_act else 0)
        + (200 if tier3_poc_high else 0)
        + (100 if tier4_critical else 0)
        + cvss_score
    )

    return {
        "priority": priority_score,
        "alert": is_alert,
        "cve": cve_id,
        "cvss": round(cvss_score, 1),
        "product": product_str,
        "kev": is_kev,
        "ssvc": {
            "exp": ssvc_exp,
            "auto": ssvc_auto,
            "imp": ssvc_imp,
        },
        "summary": summary_str,
    }


def fetch_latest_candidates(kev_set: set) -> list[dict]:
    """cisagov/vulnrichment の直近コミットから変更されたCVE JSONを取得・解析"""
    candidates = []
    seen_files = set()

    resp = requests.get(VULNRICHMENT_COMMITS_URL, headers=get_headers(), timeout=10)
    resp.raise_for_status()
    commits = resp.json()

    for c in commits:
        sha = c.get("sha")
        if not sha:
            continue
        c_resp = requests.get(
            f"https://api.github.com/repos/cisagov/vulnrichment/commits/{sha}",
            headers=get_headers(),
            timeout=10,
        )
        if c_resp.status_code != 200:
            continue

        files = c_resp.json().get("files", [])
        for f in files:
            fname = f.get("filename", "")
            raw_url = f.get("raw_url", "")
            if not fname.endswith(".json") or "CVE-" not in fname or fname in seen_files:
                continue
            seen_files.add(fname)

            try:
                raw_resp = requests.get(raw_url, timeout=8)
                if raw_resp.status_code == 200:
                    parsed = parse_cve5_json(raw_resp.json(), kev_set)
                    if parsed:
                        candidates.append(parsed)
            except Exception as e:
                print(f"[WARN] Failed to parse {fname}: {e}")

            if len(seen_files) >= 35:  # API負荷と実行時間を抑えるため直近35件まで検査
                break
        if len(seen_files) >= 35:
            break

    return candidates


def get_current_gist() -> dict:
    """現在Gistに保存されているJSONを取得（同じCVEで何度もseqを上げないため）"""
    if not GIST_ID:
        return {}
    try:
        resp = requests.get(f"https://api.github.com/gists/{GIST_ID}", headers=get_headers(), timeout=10)
        if resp.status_code == 200:
            content = resp.json().get("files", {}).get(GIST_FILENAME, {}).get("content", "{}")
            return json.loads(content)
    except Exception:
        pass
    return {}


def update_gist(payload: dict):
    """Gist上の vuln_alert.json を更新"""
    if not GIST_ID or not GH_TOKEN:
        print("[INFO] Dry-run output (Set GIST_ID and GH_TOKEN to update Gist):")
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    body = {
        "files": {
            GIST_FILENAME: {
                "content": json.dumps(payload, indent=2, ensure_ascii=False)
            }
        }
    }
    resp = requests.patch(
        f"https://api.github.com/gists/{GIST_ID}",
        headers=get_headers(),
        json=body,
        timeout=10,
    )
    resp.raise_for_status()
    print(f"[SUCCESS] Updated Gist {GIST_ID} with {payload['cve']} (seq={payload['seq']}, alert={payload['alert']})")


def main():
    now_str = datetime.now(JST).strftime("%m/%d %H:%M")

    # LT本番デモ用： python fetch_vuln.py --mock-alert で強制的に緊急アラートを発火！
    if "--mock-alert" in sys.argv:
        payload = {
            "seq": int(time.time()),
            "updated_at": now_str,
            "alert": True,
            "cve": "CVE-2026-9999",
            "cvss": 10.0,
            "product": "Internal CTF Gateway",
            "kev": True,
            "ssvc": {"exp": "active", "auto": "yes", "imp": "total"},
            "summary": "[LIVE DEMO] Unauthenticated remote code execution actively exploited in the wild.",
        }
        update_gist(payload)
        return

    kev_set = fetch_kev_set()
    candidates = fetch_latest_candidates(kev_set)
    if not candidates:
        print("[INFO] No CVE candidates found.")
        return

    # 最も優先度スコアが高い1件を選出
    candidates.sort(key=lambda x: x["priority"], reverse=True)
    best = candidates[0]
    best.pop("priority", None)

    current_gist = get_current_gist()
    prev_cve = current_gist.get("cve")
    prev_seq = current_gist.get("seq", int(time.time()))

    # 新しいCVEに変わった場合のみ seq を現在時刻に更新（同じCVEならseqを維持して再鳴動を防止）
    new_seq = int(time.time()) if best["cve"] != prev_cve else prev_seq

    payload = {
        "seq": new_seq,
        "updated_at": now_str,
        **best,
    }
    update_gist(payload)


if __name__ == "__main__":
    main()
