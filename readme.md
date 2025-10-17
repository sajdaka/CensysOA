🔒 Security JSON Summarizer
A Python-based tool for intelligent summarization and analysis of security scan data from network hosts. This tool processes JSON files containing host vulnerability data, threat intelligence, and service information to generate comprehensive security reports using GPT-based AI summarization.

Intelligent Chunking: Automatically splits large JSON files into processable chunks while maintaining context
Vulnerability Prioritization: Identifies and prioritizes critical security threats, including malware detection
Multi-Strategy Processing:

Prioritize by vulnerability severity
Group by Autonomous System Number (ASN)
Sequential processing


Token Optimization: Reduces token usage by up to 70% through intelligent field selection
Scalable Architecture: Handles files from a few hosts to thousands

Security Analysis

Critical vulnerability detection (CVE tracking)
Malware identification (including C2 servers)
Threat intelligence integration
Risk level assessment
Service exposure analysis
Certificate validation checks

User Interface

GUI Application: User-friendly tkinter interface
Multi-tab Output: Executive summary, chunk details, and raw JSON views
Real-time Statistics: Token usage, chunk count, processing metrics
Export Functionality: Save reports as text or JSON

Architecture
├── JSONSummarizer
│   ├── preprocess_json()      # Analyzes JSON structure
│   ├── chunk_hosts()           # Intelligent chunking strategy
│   ├── _simplify_host_for_summary()  # Token optimization
│   ├── generate_chunk_prompt() # Context-aware prompts
│   ├── create_final_summary()  # Hierarchical summarization
│   └── process_json()          # Main processing pipeline
│
└── JSONSummarizerGUI
    ├── Control Panel           # File selection & strategy
    ├── Output Tabs            # Multiple view formats
    └── Statistics Display     # Processing metrics
Installation
Prerequisites

Python 3.8 or higher
OpenAI API key (for GPT integration)

Install Dependencies
bash conda env create -f environment.yml
For GUI support:
bashpip install tkinter  # Usually comes with Python
Clone Repository
bashgit clone https://github.com/yourusername/security-json-summarizer.git
cd security-json-summarizer
Usage
CLI Usage
pythonfrom json_summarizer import JSONSummarizer, HostSummaryConfig

# Configure processing strategy
config = HostSummaryConfig(
    prioritize_vulns=True,      # Group by vulnerability severity
    group_by_asn=False,         # Alternative: group by network
    max_hosts_per_chunk=50,     # Hosts per chunk
    max_tokens_per_chunk=3000   # Token limit per chunk
)

# Initialize summarizer
summarizer = JSONSummarizer(model="gpt-5", config=config)

# Process JSON file
result = summarizer.process_json("path/to/security_scan.json")

# Access results
print(result['executive_summary'])
print(f"Processed {result['statistics']['total_hosts']} hosts")
print(f"Created {result['statistics']['chunks_created']} chunks")
GUI Usage
bashpython gui_summarizer.py

Click Browse to select your JSON file
Choose processing strategy from dropdown
Click Process JSON to analyze
View results in different tabs:

Executive Summary: High-level security report
Chunk Details: Processing breakdown
Raw Output: Complete JSON response


Click Export Summary to save results

Input Format
The tool expects JSON files with the following structure:
json{
  "metadata": {
    "description": "Security scan data",
    "created_at": "2025-01-12",
    "hosts_count": 3
  },
  "hosts": [
    {
      "ip": "192.168.1.1",
      "location": {
        "country": "United States",
        "city": "New York"
      },
      "autonomous_system": {
        "asn": 12345,
        "name": "Example ASN"
      },
      "services": [
        {
          "port": 22,
          "protocol": "SSH",
          "software": [
            {
              "product": "openssh",
              "version": "8.7"
            }
          ],
          "vulnerabilities": [
            {
              "cve_id": "CVE-2023-38408",
              "severity": "critical",
              "cvss_score": 9.8
            }
          ]
        }
      ],
      "threat_intelligence": {
        "risk_level": "high",
        "malware_families": ["Cobalt Strike"]
      }
    }
  ]
}
📊 Output Format
The tool generates a comprehensive report containing:
json{
  "executive_summary": "Security analysis summary...",
  "metadata": {...},
  "chunk_details": [
    {
      "type": "critical",
      "chunk_id": "a1b2c3d4",
      "host_count": 5,
      "summary": "Analysis of critical hosts..."
    }
  ],
  "statistics": {
    "total_hosts": 100,
    "chunks_created": 5,
    "total_tokens_used": 12500,
    "processing_strategy": {
      "prioritize_vulns": true,
      "max_hosts_per_chunk": 50
    }
  }
}
⚙️ Configuration
HostSummaryConfig Options
ParameterTypeDefaultDescriptionprioritize_vulnsboolTrueGroup hosts by vulnerability severitygroup_by_asnboolFalseGroup hosts by Autonomous System Numbermax_hosts_per_chunkint50Maximum hosts per processing chunkmax_tokens_per_chunkint3000Token limit per chunk
Processing Strategies

Prioritize Vulnerabilities (Default)

Critical hosts with malware: 20 hosts/chunk
High-risk hosts: 30 hosts/chunk
Normal hosts: 50 hosts/chunk


Group by ASN

Analyzes hosts within same network
Useful for network-wide security assessment


Sequential

Processes hosts in order
Best for small datasets



API Setup
OpenAI Configuration

Get your API key from OpenAI Platform
Add to your code:

pythondef call_gpt_api(self, prompt: str) -> str:
    import openai
    openai.api_key = "your-api-key-here"  # Use environment variable in production
    
    response = openai.ChatCompletion.create(
        model=self.model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,  # Lower for consistent summaries
        max_tokens=500
    )
    return response.choices[0].message.content

Or use environment variable:

bashexport OPENAI_API_KEY="your-api-key-here"
Examples
Example 1: Analyzing Critical Infrastructure
python# Focus on critical vulnerabilities
config = HostSummaryConfig(
    prioritize_vulns=True,
    max_hosts_per_chunk=20  # Smaller chunks for detailed analysis
)

summarizer = JSONSummarizer(config=config)
result = summarizer.process_json("critical_infrastructure.json")
Example 2: Network-Wide Analysis
python# Group by ASN for network patterns
config = HostSummaryConfig(
    group_by_asn=True,
    max_hosts_per_chunk=100  # Larger chunks for network analysis
)

summarizer = JSONSummarizer(config=config)
result = summarizer.process_json("network_scan.json")
Performance
Token Optimization Results
Data SizeOriginal TokensOptimized TokensReductionSmall (3 hosts)4,5001,20073%Medium (50 hosts)75,00020,00073%Large (500 hosts)750,000200,00073%
Processing Times

Small files (<10 hosts): ~5 seconds
Medium files (10-100 hosts): ~30 seconds
Large files (100-1000 hosts): ~2-5 minutes

Note: Times depend on API response speed

# Install dependencies
conda env create -f environment.yml

License
This project is licensed under the MIT License - see the LICENSE file for details.
Acknowledgments

OpenAI for GPT API
Tiktoken for token counting
Security community for vulnerability databases


Known Issues

Large files (>1000 hosts) may require chunked API calls
Token limits may require adjustment for very detailed vulnerability data
GUI requires tkinter (included in most Python installations)

Roadmap

 Add support for multiple file formats (CSV, XML)
 Implement caching for repeated analyses
 Add real-time streaming for large file processing
 Integrate with popular security scanning tools
 Add customizable report templates
 Implement parallel processing for chunks
