
import sqlite3
from rich.console import Console
from rich.table import Table

def view_history(db_path='pitt_results.db'):
    """Displays a summary of all past test runs from the database."""
    console = Console()
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT run_timestamp, target_url FROM test_runs ORDER BY run_timestamp DESC")
            runs = cursor.fetchall()

            if not runs:
                console.print("[yellow]No history found.[/yellow]")
                return

            table = Table(title="PITT Test Run History")
            table.add_column("Run Timestamp", style="cyan")
            table.add_column("Target URL", style="magenta")
            table.add_column("Vulnerabilities Found", style="red")

            for run in runs:
                cursor.execute("SELECT COUNT(*) FROM test_runs WHERE run_timestamp = ? AND result = 'Vulnerable'", (run['run_timestamp'],))
                vuln_count = cursor.fetchone()[0]
                table.add_row(run['run_timestamp'], run['target_url'], str(vuln_count))
            
            console.print(table)

    except sqlite3.Error as e:
        console.print(f"[bold red]Database error: {e}[/bold red]")

if __name__ == "__main__":
    view_history()
