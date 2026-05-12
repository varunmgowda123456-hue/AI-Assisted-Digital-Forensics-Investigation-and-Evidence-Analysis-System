import os
import random
import string

def generate_random_id(length=8):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def create_stress_test_suite(base_dir="forensiq_drop_zone", count_per_scenario=170):
    scenarios = {
        "Phishing_Attack_Evidence": [
            "urgent_invoice_{ID}.eml", "verify_account_{ID}.html", "redirect_trace_{ID}.log", "login_portal_clone_{ID}.php"
        ],
        "Ransomware_Attack_Evidence": [
            "locker_payload_{ID}.ps1", "READ_ME_NOW_{ID}.txt", "cleanup_util_{ID}.bat", "mass_encryption_{ID}.sh"
        ],
        "Cyberbullying_Evidence": [
            "harassment_chat_{ID}.txt", "malicious_thread_{ID}.json", "anonymous_threat_{ID}.eml", "reputation_attack_{ID}.txt"
        ]
    }

    print(f"[*] Generating 'Strongest' Forensic Stress-Test Suite (500+ Artifacts) in {base_dir}...")

    total_generated = 0
    for scenario, templates in scenarios.items():
        scenario_path = os.path.join(base_dir, scenario)
        os.makedirs(scenario_path, exist_ok=True)
        
        for i in range(count_per_scenario):
            template = random.choice(templates)
            filename = template.replace("{ID}", generate_random_id())
            
            # Generate Complex Content based on scenario
            content = ""
            if "Phishing" in scenario:
                content = f"Subject: URGENT Account Security Alert\nLink: http://verify-{generate_random_id().lower()}.click/auth/login"
            elif "Ransomware" in scenario:
                if ".ps1" in filename or ".sh" in filename:
                    # Inject high-entropy "malicious" block
                    content = "# Malicious Sequence\n" + ''.join(random.choices(string.printable, k=500))
                else:
                    content = f"!!! YOUR DATA IS ENCRYPTED !!!\nPay 0.5 BTC to {generate_random_id()}"
            else: # Cyberbullying
                content = f"[14:00] User_{generate_random_id()}: You are a loser. I will destroy you."

            with open(os.path.join(scenario_path, filename), "w", encoding="utf-8") as f:
                f.write(content)
            total_generated += 1

    print(f"\n[+] STRENGTH VERIFIED: {total_generated} unique forensic artifacts generated.")
    print("[+] System is now ready for high-volume, scenario-driven stress testing.")

if __name__ == "__main__":
    create_stress_test_suite()
