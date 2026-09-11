from datetime import datetime

def generate_html_report(results, output_file="compliance_report.html"):
    total = len(results)
    passed = sum(1 for r in results if r['status'] == 'PASS')
    failed = sum(1 for r in results if r['status'] == 'FAIL')
    compliance_pct = round((passed / total) * 100) if total > 0 else 0

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows_html = ""
    for r in results:
        status_class = "pass" if r['status'] == 'PASS' else "fail"
        rows_html += f"""
        <tr class="{status_class}">
            <td>{r['resource']}</td>
            <td class="status-badge">{r['status']}</td>
            <td>{r['detail']}</td>
            <td>{r['pci_requirement']}</td>
        </tr>
        """

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>PCI-DSS Compliance Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 40px;
                background-color: #f4f4f4;
                color: #222;
            }}
            h1 {{
                color: #1a1a2e;
            }}
            .meta {{
                color: #555;
                margin-bottom: 20px;
            }}
            .summary {{
                display: flex;
                gap: 20px;
                margin-bottom: 30px;
            }}
            .summary-box {{
                background: white;
                border-radius: 8px;
                padding: 20px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                text-align: center;
                flex: 1;
            }}
            .summary-box h2 {{
                margin: 0;
                font-size: 32px;
            }}
            .summary-box p {{
                margin: 5px 0 0;
                color: #666;
            }}
            .score {{
                color: {'#2ecc71' if compliance_pct >= 70 else '#e67e22' if compliance_pct >= 40 else '#e74c3c'};
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                background: white;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            th, td {{
                text-align: left;
                padding: 12px 15px;
                border-bottom: 1px solid #eee;
            }}
            th {{
                background-color: #1a1a2e;
                color: white;
            }}
            tr.fail {{
                background-color: #fdecea;
            }}
            tr.pass {{
                background-color: #eafaf1;
            }}
            .status-badge {{
                font-weight: bold;
            }}
            tr.fail .status-badge {{
                color: #e74c3c;
            }}
            tr.pass .status-badge {{
                color: #27ae60;
            }}
        </style>
    </head>
    <body>
        <h1>PCI-DSS Compliance Report</h1>
        <p class="meta">Generated: {timestamp}</p>

        <div class="summary">
            <div class="summary-box">
                <h2>{total}</h2>
                <p>Total Checks</p>
            </div>
            <div class="summary-box">
                <h2 style="color:#27ae60;">{passed}</h2>
                <p>Passed</p>
            </div>
            <div class="summary-box">
                <h2 style="color:#e74c3c;">{failed}</h2>
                <p>Failed</p>
            </div>
            <div class="summary-box">
                <h2 class="score">{compliance_pct}%</h2>
                <p>Compliance Score</p>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Resource</th>
                    <th>Status</th>
                    <th>Detail</th>
                    <th>PCI-DSS Requirement</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
    </body>
    </html>
    """

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Report generated: {output_file}")