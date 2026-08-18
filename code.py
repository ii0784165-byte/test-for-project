import os
import requests
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
OTX_API_KEY = os.getenv("ALIENVAULT_OTX_API_KEY")

now = datetime.now(timezone.utc)
twenty_four_hours_ago = now - timedelta(hours=24)


def fetch_alienvault_iocs():
    print("AlienVault OTX-dən məlumatlar çəkilir...")
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    response = requests.get(url, headers=headers)
    iocs = []

    if response.status_code == 200:
        data = response.json()
        results = data.get("results", [])
        for pulse in results:
            modified_str = pulse.get("modified")
            if modified_str:
                # ISO formatındakı vaxtı parsing edib UTC zaman qurşağına çeviririk
                try:
                    pulse_time = datetime.fromisoformat(modified_str.replace("Z", "+00:00"))
                    if pulse_time.tzinfo is None:
                        pulse_time = pulse_time.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
                if pulse_time >= twenty_four_hours_ago:
                    for indicator in pulse.get("indicators", []):
                        iocs.append({
                            "source": "AlienVault OTX",
                            "type": indicator.get("type"),
                            "indicator": indicator.get("indicator")
                        })
        print(f"AlienVault OTX-dən {len(iocs)} ədəd IOC tapıldı.")
    else:
        print(f"AlienVault Xətası: {response.status_code}")
    return iocs


def fetch_virustotal_iocs():
    print("VirusTotal API ilə əlaqə yaradılır...")
    url = "https://www.virustotal.com/api/v3/popular_threat_categories"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }

    response = requests.get(url, headers=headers)
    iocs = []

    if response.status_code == 200:
        print("VirusTotal API bağlantısı uğurludur.")
    else:
        print(f"VirusTotal Xətası: {response.status_code}")
    return iocs


def normalize_and_deduplicate(iocs):
    """
    Xam IOC siyahısını normallaşdırır və eyni indikatorları (IP/domen/hash)
    bir yerə toplayır.

    Nümunə: bir IP 15 fərqli pulse/mənbədə rast gəlinibsə, nəticədə bu IP
    YALNIZ BİR DƏFƏ görünəcək, amma "occurrences": 15 sahəsi ilə bu tezliyi
    saxlayacaq. Bu, analitik üçün çox faydalıdır, çünki tez-tez rast gəlinən
    IOC adətən daha etibarlı/kritik təhdid siqnalı sayılır.

    Qaytarır: hər elementi aşağıdakı sahələrdən ibarət lüğət olan siyahı:
        - indicator   : normallaşdırılmış (kiçik hərflərlə, boşluqsuz) IOC dəyəri
        - type        : IOC növü (ip, domain, hash və s.)
        - sources     : bu IOC-a rast gəlinən unikal mənbələrin siyahısı
        - occurrences : neçə dəfə (dedup-dan əvvəl) rast gəlinib
    Nəticə, ən çox təkrarlanan (deməli, daha vacib ola bilən) IOC-lar
    əvvəldə olacaq şəkildə sıralanır.
    """
    grouped = defaultdict(lambda: {"type": None, "sources": set(), "count": 0})

    for ioc in iocs:
        raw_indicator = ioc.get("indicator")
        if not raw_indicator:
            continue

        # Normalizasiya: boşluqları sil, kiçik hərflərə sal ki, "1.2.3.4 "
        # ilə "1.2.3.4" eyni IOC kimi tanınsın
        key = raw_indicator.strip().lower()

        entry = grouped[key]
        entry["type"] = ioc.get("type") or entry["type"]
        entry["sources"].add(ioc.get("source", "Unknown"))
        entry["count"] += 1

    deduped = []
    for indicator, data in grouped.items():
        deduped.append({
            "indicator": indicator,
            "type": data["type"],
            "sources": sorted(data["sources"]),
            "occurrences": data["count"]
        })

    deduped.sort(key=lambda item: item["occurrences"], reverse=True)
    return deduped


def print_analyst_report(deduped_iocs, top_n=20):
    """
    Kibertəhlükəsizlik analitiki üçün oxunaqlı konsol hesabatı çap edir:
    ən çox təkrarlanan (yəni ən "isti") IOC-ları önə çıxarır.
    """
    total_occurrences = sum(item["occurrences"] for item in deduped_iocs)
    duplicates_removed = total_occurrences - len(deduped_iocs)

    print("\n" + "=" * 90)
    print("KİBER TƏHDİD İNDİKATORLARI (IOC) HESABATI")
    print("=" * 90)
    print(f"{'IOC':40} {'Növ':10} {'Tezlik':8} {'Mənbələr'}")
    print("-" * 90)

    for item in deduped_iocs[:top_n]:
        indicator_display = item["indicator"][:38]
        type_display = item["type"] or "-"
        sources_display = ", ".join(item["sources"])
        print(f"{indicator_display:40} {type_display:10} {item['occurrences']:<8} {sources_display}")

    print("-" * 90)
    print(f"Unikal IOC sayı      : {len(deduped_iocs)}")
    print(f"Silinən təkrarlar    : {duplicates_removed}")
    print(f"Ümumi xam qeyd sayı  : {total_occurrences}")

    if deduped_iocs:
        most_frequent = deduped_iocs[0]
        print(
            f"\n⚠️  Ən çox rast gəlinən IOC: {most_frequent['indicator']} "
            f"({most_frequent['occurrences']} dəfə, mənbələr: {', '.join(most_frequent['sources'])})"
        )
    print("=" * 90 + "\n")


if __name__ == "__main__":
    otx_data = fetch_alienvault_iocs()
    vt_data = fetch_virustotal_iocs()

    all_iocs = otx_data + vt_data
    deduped_iocs = normalize_and_deduplicate(all_iocs)

    print_analyst_report(deduped_iocs)

    print(
        f"Məlumat toplama prosesi tamamlandı! "
        f"Xam IOC sayı: {len(all_iocs)} | Unikal IOC sayı: {len(deduped_iocs)}"
    )
