import json
from turtle import dot
# from openai import api_key
import tiktoken
from typing import List, Dict, Any, Generator, Optional
import hashlib
from dataclasses import dataclass
import os
from dotenv import load_dotenv


@dataclass
class HostSummaryConfig:
    prioritize_vulns: bool = True
    group_by_asn: bool = False
    max_hosts_per_chunk: int = 50
    max_tokens_per_chunk: int = 3000



class JSONSummarizer:
    
    def __init__(self, model="gpt-5", config: Optional[HostSummaryConfig] = None):
        self.model = model
        self.config = config or HostSummaryConfig()
        self.encoding = tiktoken.encoding_for_model(model)
    
        
    def preprocess_json(self, data: Dict) -> Dict:
        
        metadata = {k: v for k, v in data.items() if k != 'hosts'}
        hosts = data.get('hosts', [])
        
        analysis = {
            'total_hosts': len(hosts),
            'metadata': metadata,
            'unique_asns': len(set(h.get('autonomous_system', {}).get('asn', 'unknown') for h in hosts)),
            'hosts_with_vulnerabilities': sum(
                1 for h in hosts
                if any(
                    service.get('vulnerabilities', [])
                    for service in h.get('services', [])
                )
            ),
            'hosts_with_threats': sum(
                1 for h in hosts
                if h.get('threat_intelligence', {}).get('risk_level') in ['high', 'critical', 'medium']
                or h.get('threat_intelligence', {}).get('malware_families')
                or any(
                    service.get('malware_detected')
                    for service in h.get('services', [])
                )
            ),
            'unique_locations': len(set(h.get('location', {}).get('country', 'unknown') for h in hosts))
        }
        
        return analysis
    
    
    def chunk_hosts(self, hosts: List[Dict]) -> List[Dict]:
        
        chunks = []
        
        if self.config.prioritize_vulns:
            
            critical_hosts = [h for h in hosts 
                              if any(
                                  vuln.get('severity') in ['high', 'critical']
                                  for service in h.get('services', [])
                                  for vuln in service.get('vulnerabilities', [])
                              ) or h.get('threat_intelligence', {}).get('risk_level') in ['high', 'critical']
                              ]
            normal_hosts = [h for h in hosts if h not in critical_hosts]
            
            chunks.extend(self._create_chunks(critical_hosts, max_hosts= 20, chunk_type='critical'))
            chunks.extend(self._create_chunks(normal_hosts, max_hosts=self.config.max_hosts_per_chunk, chunk_type='normal'))
            
            
        elif self.config.group_by_asn:
            
            from collections import defaultdict
            asn_groups = defaultdict(list)
            
            for host in hosts:
                asn = host.get('autonomous_system', {}).get('asn', 'unknown') 
                asn_groups[asn].append(host)
            
            for asn, asn_hosts in asn_groups.items():
                chunks.extend(self._create_chunks(asn_hosts, max_hosts=self.config.max_hosts_per_chunk, chunk_type= f"asn_{asn}"))
                
        else:
            chunks.extend(self._create_chunks(hosts, max_hosts= self.config.max_hosts_per_chunk, chunk_type="sequential")) 
            
        return chunks
    
    
    def _create_chunks(self, hosts: List[Dict], max_hosts: int, chunk_type: str) -> List[Dict]:
        
        chunks = []
        current_chunk = []
        current_tokens = 0
        
        for host in hosts:
            
            host_simple = self._simplify_host_for_summary(host)
            host_tokens = len(self.encoding.encode(json.dumps(host_simple)))
            
            if (len(current_chunk) >= max_hosts or 
                current_tokens + host_tokens > self.config.max_tokens_per_chunk) and current_chunk:
                
                chunks.append({
                    'type': chunk_type,
                    'hosts': current_chunk,
                    'host_count': len(current_chunk),
                    'token_count': current_tokens,
                    'chunk_id': hashlib.md5(f"{chunk_type}_{len(chunks)}".encode()).hexdigest()[:8]
                }) 
                current_chunk = []
                current_tokens = 0
                
            current_chunk.append(host_simple)
            current_tokens += host_tokens
            
        if current_chunk:
            chunks.append({
                'type': chunk_type,
                'hosts': current_chunk,
                'host_count': len(current_chunk),
                'token_count': current_tokens,
                'chunk_id': hashlib.md5(f"{chunk_type}_{len(chunks)}".encode()).hexdigest()[:8]
            })      
            
        return chunks
    
    
    def _simplify_host_for_summary(self, host: Dict) -> Dict:
        
        simplified = {
            'ip': host.get('ip'),
            'location': host.get('location', {}).get('country'),
            'asn': host.get('autonomous_system', {}).get('asn'),
            'asn_name': host.get('autonomous_system', {}).get('name')
        }
        
        if dns:= host.get('dns', {}).get('hostname'):
            simplified['hostname'] = dns
            
        services = host.get('services', [])
        if not services:
            return simplified
            
        service_summary = []
        total_vulns = []
        malware_detected = False
        
        
        for service in services:
            svc_info = {
                'port': service.get('port'),
                'protocol': service.get('protocol')
            }
            
            if software_list := service.get('software'):
                software = software_list[0] if software_list else {}
                svc_info['software'] = f"{software.get('product', 'unknown')} {software.get('version', '')}".strip()
                
            if vulns := service.get('vulnerabilities', []):
                total_vulns.extend(vulns)
                critical_vulns = [v for v in vulns if v.get('severity') in ['critical', 'high']]
                if critical_vulns:
                    svc_info['critical_vulns'] = [v.get('cve_id') for v in critical_vulns[:2]]
                svc_info['vuln_count'] = len(vulns)
                
            if malware := service.get('malware_detected'):
                malware_detected = True
                svc_info['malware'] = {
                    'name': malware.get('name'),
                    'type': malware.get('type'),
                    'threat_actors': malware.get('threat_actors', [])[:2]
                }  
                
            if service.get('authentication_required') or service.get('access_restricted'):
                svc_info['access_restricted'] = True
                
            if service.get('tls_enabled'):
                svc_info['tls'] = True
                if cert := service.get('certificate'):
                    if cert.get('self_signed'):
                        svc_info['self_signed_cert'] = True
                        
            service_summary.append(svc_info)
            
        simplified['services'] = service_summary
        simplified['total_services'] = len(service_summary)
        
        if total_vulns:
            severity_counts = {}
            for vuln in total_vulns:
                sev = vuln.get('severity', 'unknown')
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                
            simplified['vulnerability_summary'] = {
                'total': len(total_vulns),
                'breakdown': severity_counts,
                'critical_cves': list(set(
                    v.get('cve_id') for v in total_vulns
                    if v.get('severity') == 'critical'
                ))
            }
            
        if threat_intel := host.get('threat_intelligence', {}):
            simplified['threat_intel'] = {
                'risk_level': threat_intel.get('risk_level'),
                'labels': threat_intel.get('security_labels', []),
            }
            if malware_families := threat_intel.get('malware_families'):
                simplified['threat_intel']['malware'] = malware_families
                
        if malware_detected:
            simplified['MALWARE_DETECTED'] = True
            
        return simplified
    
    def generate_chunk_prompt(self, chunk: Dict, analysis: Dict) -> str:
        
        if chunk['type'] == 'critical':
            return f"""
            Analyze these HIGH-PRIORITY hosts with vulnerabilities or threat indicators:
            
            Total hosts in dataset: {analysis['total_hosts']}
            This chunk: {chunk['host_count']} critical hosts
            
            Data:
            {json.dumps(chunk['hosts'], indent=2)}
            
            Focus on:
            1. Critical vulnerabilities (CVEs, severity)
            2. Threat intelligence findings
            3. Common attack patterns or exposures
            4. Recommended immediate actions
            
            Provide a security-focused summary.
            """
        elif chunk['type'].startswith('asn_'):
            return f"""
            Analyze hosts from the same Autonomous System network:
            
            ASN: {chunk['type'].replace('asn_', '')}
            Host count: {chunk['host_count']}
            
            Data:
            {json.dumps(chunk['hosts'], indent=2)}
            
            Focus on:
            1. Network-wide patterns
            2. Common services or configurations
            3. Geographical distribution
            4. Overall security posture of this network
            
            Provide a network-centric summary.
            """
            
        else:
            return f"""
            Summarize this batch of hosts from a larger security scan:
            
            Batch size: {chunk['host_count']} hosts
            Total dataset: {analysis['total_hosts']} hosts
            
            Data:
            {json.dumps(chunk['hosts'], indent=2)}
            
            Provide a concise summary highlighting:
            1. Service distribution
            2. Vulnerability statistics
            3. Geographical spread
            4. Any notable security concerns
            """
            
    def create_final_summary(self, chunk_summaries: List[Dict], analysis: Dict) -> str:
        
        critical_summaries = [s for s in chunk_summaries if s.get('type') == 'critical']
        other_summaries = [s for s in chunk_summaries if s.get('type') != 'critical']
        
        prompt = f"""
        Create an executive security summary from these analyzed chunks:
        
        METADATA:
        {json.dumps(analysis['metadata'], indent=2)}
        
        OVERALL STATISTICS:
        - Total hosts scanned: {analysis['total_hosts']}
        - Unique AS Networks: {analysis['unique_asns']}
        - Hosts with vulnerabilities: {analysis['hosts_with_vulnerabilities']}
        - Hosts with threat intelligence: {analysis['hosts_with_threats']}
        
        {"CRITICAL HOST FINDINGS:" if critical_summaries else ""}
        {chr(10).join([s['summary'] for s in critical_summaries])}
        
        NETWORK ANALYSIS:
        {chr(10).join([s['summary'] for s in other_summaries])}
        
        Generate a comprehensive security report with:
        1. Executive Summary (2-3 sentences)
        2. Critical Findings
        3. Risk Assessment
        4. Recommended Actions
        5. Statistical Overview
        """
        
        return self.call_gpt_api(prompt)
    
    def process_json(self, file_path: str) -> Dict:
        
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        analysis = self.preprocess_json(data)
        
        hosts = data.get('hosts', [])
        chunks = self.chunk_hosts(hosts)
        
        chunk_summaries = []
        for chunk in chunks:
            prompt = self.generate_chunk_prompt(chunk, analysis)
            summary = self.call_gpt_api(prompt)
            
            chunk_summaries.append({
                'type': chunk['type'],
                'chunk_id': chunk['chunk_id'],
                'host_count': chunk['host_count'],
                'summary': summary
            })
            
        final_summary = self.create_final_summary(chunk_summaries, analysis)
        
        return {
            'executive_summary': final_summary,
            'metadata': analysis['metadata'],
            'chunk_details': chunk_summaries,
            'statistics': {
                'total_hosts': analysis['total_hosts'],
                'chunks_created': len(chunks),
                'total_tokens_used': sum(c['token_count'] for c in chunks),
                'processing_strategy': self.config.__dict__
            }
        }
        
    def call_gpt_api(self, prompt: str) -> str:
        from openai import OpenAI
        load_dotenv(dotenv_path="env/.env")
        
        client = OpenAI()
        
 
        response = client.chat.completions.create(
            model="gpt-5",  
            messages=[
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=1000
        )
        
        # Extract and return the text content
        return response.choices[0].message.content
        
