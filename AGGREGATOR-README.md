# NetworkAuditAggregator

Aggregates audit results from multiple systems into consolidated client-ready reports.

## Overview

The NetworkAuditAggregator processes JSON audit files from WindowsWorkstationAuditor and WindowsServerAuditor to generate executive-level reports suitable for client deliverables. Combines findings across multiple systems with risk prioritization and professional formatting.

## Usage

### Basic Usage
```powershell
# Process audit files in import folder
.\src\NetworkAuditAggregator.ps1 -ClientName "Example Client"

# Custom paths
.\src\NetworkAuditAggregator.ps1 -ImportPath "C:\Audits\JSON" -OutputPath "C:\Reports" -ClientName "Client Name"
```

### Directory Structure
```
import/                    # Drop JSON audit files here
├── COMPUTER1_20250114_143022_raw_data.json
├── COMPUTER2_20250114_143156_raw_data.json
└── SERVER01_20250114_144233_raw_data.json

output/                    # Generated reports appear here
└── Client-Name-IT-Assessment-Report-2025-01-14.html
```

## Features

### Executive Summary
- High-level metrics and risk distribution
- Environment overview (workstations/servers/domain controllers)
- Priority recommendations with timeframes

### Scoring Matrix
- Component-based scoring (1-5 scale)
- Criticality assessment by category
- Adherence ratings matching professional consulting format

### Risk Analysis
- Color-coded HIGH/MEDIUM/LOW risk sections
- Specific findings with affected system counts
- Actionable recommendations per risk item

### Systems Overview
- Letter grades (A-F) per system and category
- Visual snapshot of environment health
- Individual system risk counts

## Report Output

Generated HTML reports include:
- Professional styling matching client deliverable format
- Print-friendly layouts
- Copy-friendly tables for Word integration
- Executive dashboard with key metrics
- Technical details organized by risk level

## Configuration

Modify `config/aggregator-config.json` to customize:
- Scoring thresholds and risk levels
- Report styling and color schemes  
- Client branding and contact information
- File processing preferences

## Requirements

- PowerShell 5.0+
- JSON audit files from WindowsWorkstationAuditor or WindowsServerAuditor
- Modern web browser to view HTML reports

## Integration Workflow

1. **Run Audits**: Execute workstation/server auditors on target systems
2. **Collect JSON**: Copy `*_raw_data.json` files to `import/` folder  
3. **Generate Report**: Run aggregator with client name
4. **Deliver Results**: Professional HTML report ready for client presentation

## Future Enhancements

- **Database Integration**: SQLite/SQL Server backends for historical analysis
- **REST API**: Direct upload from audit tools
- **Power BI Templates**: Automated dashboard generation
- **Word Templates**: Direct .docx report generation
- **Trend Analysis**: Multi-assessment comparisons over time