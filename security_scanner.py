import socket
import requests


def check_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((host, port))

        sock.close()

        return result == 0

    except:
        return False


def analyze_security_headers(response):

    headers = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "X-Frame-Options",
        "X-Content-Type-Options": "X-Content-Type-Options"
    }

    observations = []
    recommendations = []
    score = 0

    print("\n▶ SECURITY HEADER ANALYSIS")
    print("────────────────────────────────────────────")

    for header, name in headers.items():

        if header in response.headers:

            print(f"{name:<25} PRESENT")
            score += 10

        else:

            print(f"{name:<25} NOT DETECTED")

            observations.append(
                f"{name} header was not detected in this response."
            )

            recommendations.append(
                f"Review and verify {name} configuration."
            )

    return score, observations, recommendations


def main():

    target = input("Enter Website (example: google.com): ").strip()

    observations = []
    recommendations = []
    score = 0

    try:

        ip = socket.gethostbyname(target)

        print("\n")
        print("╔══════════════════════════════════════════════════════╗")
        print("║              WEB SECURITY SCANNER REPORT             ║")
        print("╚══════════════════════════════════════════════════════╝")

        print("\n▶ TARGET INFORMATION")
        print("────────────────────────────────────────────")

        print(f"Domain      : {target}")
        print(f"IP Address  : {ip}")

        print("\n▶ NETWORK ANALYSIS")
        print("────────────────────────────────────────────")

        # Port 80
        if check_port(ip, 80):

            print("Port 80  (HTTP)  : OPEN")

            observations.append(
                "Port 80 is accessible."
            )

            recommendations.append(
                "Verify HTTP traffic is redirected to HTTPS."
            )

            score += 10

        else:

            print("Port 80  (HTTP)  : CLOSED")

        # Port 443
        if check_port(ip, 443):

            print("Port 443 (HTTPS) : OPEN")

            observations.append(
                "Port 443 is accessible and HTTPS services appear available."
            )

            score += 20

        else:

            print("Port 443 (HTTPS) : CLOSED")

            recommendations.append(
                "Enable HTTPS services on Port 443 if appropriate."
            )

        print("\n▶ HTTPS ANALYSIS")
        print("────────────────────────────────────────────")

        try:

            url = "https://" + target

            response = requests.get(
                url,
                timeout=5,
                headers={
                    "User-Agent": "Mozilla/5.0"
                }
            )

            print("HTTPS Reachable : YES")
            print(f"Status Code     : {response.status_code}")

            if 200 <= response.status_code < 300:

                observations.append(
                    "Website responded successfully over HTTPS."
                )

                score += 30

            elif 300 <= response.status_code < 400:

                observations.append(
                    "Website responded with an HTTP redirect."
                )

                score += 20

            else:

                observations.append(
                    f"Website returned HTTP status {response.status_code}."
                )

            header_score, header_observations, header_recommendations = (
                analyze_security_headers(response)
            )

            score += header_score

            observations.extend(header_observations)
            recommendations.extend(header_recommendations)

        except Exception:

            print("HTTPS Reachable : NO")

            observations.append(
                "HTTPS connection could not be established."
            )

            recommendations.append(
                "Verify SSL/TLS configuration."
            )

        print("\n▶ SECURITY OBSERVATIONS")
        print("────────────────────────────────────────────")

        if len(observations) == 0:

            print("No observations recorded.")

        else:

            for i, item in enumerate(observations, start=1):
                print(f"{i}. {item}")

        print("\n▶ RECOMMENDATIONS")
        print("────────────────────────────────────────────")

        unique_recommendations = list(set(recommendations))

        if len(unique_recommendations) == 0:

            print("No recommendations at this time.")

        else:

            for i, item in enumerate(unique_recommendations, start=1):
                print(f"{i}. {item}")

        print("\n▶ FINAL ASSESSMENT")
        print("────────────────────────────────────────────")

        if score > 100:
            score = 100

        print(f"Security Score : {score}/100")

        if score >= 80:
            risk = "LOW"

        elif score >= 50:
            risk = "MEDIUM"

        else:
            risk = "HIGH"

        print(f"Risk Level     : {risk}")

        print("\nScan Completed Successfully.")

    except Exception:

        print("\nUnable to resolve domain.")
        print("Please enter a valid website address.")


if __name__ == "__main__":
    main()