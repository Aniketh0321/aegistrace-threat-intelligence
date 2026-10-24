
"""Generate a modern dashboard using the AegisTrace pipeline."""

from aegistrace.main import run
from aegistrace.dashboard_generator_modern import generate_modern_dashboard


def main() -> None:
    print("Starting AegisTrace pipeline...")

    result = run(
        enrich=False,
        forecast=True,
        output="dashboard_original.html",
        csv_path="iocs_enriched.csv",
    )

    path = generate_modern_dashboard(
        threats=result.threats,
        predictions=result.predictions,
        iocs_enriched=result.iocs_enriched,
        output_file="dashboard_modern.html",
    )

    print("\nDashboard generated successfully!")
    print(f"Modern dashboard: {path}")
    print(f"Threat records: {len(result.threats)}")
    print(f"Indicators: {len(result.iocs_enriched)}")
    print("\nOpen dashboard_modern.html in your browser to preview it.")


if __name__ == "__main__":
    main()
