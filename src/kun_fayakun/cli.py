# Bismillah ir-Rahman ir-Rahim
"""
Kun Fayakun CLI -- unified entry point for all instruments.

Usage:
    kun fatima encode <path>        Encode a file with 154-layer protection
    kun fatima verify <path>        Verify a sealed file's integrity
    kun bayyinah scan <path>        Scan files for integrity violations
    kun furqan lint <path>          Lint a codebase for structural honesty
    kun habl status                 Show journal status
    kun eess dispatch <decision>    Run dispatch lifecycle
    kun shahid report <path>        Generate transparency report
"""
import sys


def main():
    """Entry point for the kun command."""
    # Suppress banner when machine-readable output is requested
    machine_output = any(
        sys.argv[i] == "--format" and i + 1 < len(sys.argv)
        and sys.argv[i + 1] in ("json", "sarif")
        for i in range(len(sys.argv))
    )
    if not machine_output:
        print("Bismillah ir-Rahman ir-Rahim")
        print()

    if len(sys.argv) < 2:
        print("Kun Fayakun -- Be, and it is.")
        print()
        print("Usage: kun <instrument> <command> [args]")
        print()
        print("Instruments:")
        print("  fatima     Divine protection encoder")
        print("  bayyinah   Integrity scanner")
        print("  furqan     Structural honesty linter")
        print("  habl       Append-only binding ledger")
        print("  eess       Safety-critical dispatch engine")
        print("  shahid     Witness transparency reports")
        print()
        print("Run 'kun <instrument> --help' for instrument-specific commands.")
        print()
        print("Bismillah ir-Rahman ir-Rahim")
        return 0

    instrument = sys.argv[1].lower()

    if instrument == "fatima":
        from kun_fayakun.fatima import cli as fatima_cli
        return fatima_cli.run(sys.argv[2:])
    elif instrument == "bayyinah":
        from kun_fayakun.bayyinah import cli as bayyinah_cli
        return bayyinah_cli.run(sys.argv[2:])
    elif instrument == "furqan":
        from kun_fayakun.furqan import cli as furqan_cli
        return furqan_cli.run(sys.argv[2:])
    elif instrument == "habl":
        from kun_fayakun.habl import cli as habl_cli
        return habl_cli.run(sys.argv[2:])
    elif instrument == "eess":
        from kun_fayakun.eess import cli as eess_cli
        return eess_cli.run(sys.argv[2:])
    elif instrument == "shahid":
        from kun_fayakun.shahid import cli as shahid_cli
        return shahid_cli.run(sys.argv[2:])
    else:
        print(f"Unknown instrument: {instrument}")
        print("Available: fatima, bayyinah, furqan, habl, eess, shahid")
        return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
# Bismillah ir-Rahman ir-Rahim
