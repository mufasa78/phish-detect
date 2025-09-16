import pandas as pd
import re
from typing import Dict, List

class PhishingDetector:
    """Detector for phishing content in emails"""
    
    def __init__(self, setup_df: pd.DataFrame):
        """
        Initialize with setup data
        
        Args:
            setup_df (pd.DataFrame): DataFrame with columns: start_segment, end_segment, suspicious_phrase
        """
        self.setup_rules = setup_df
        self.results = {
            'is_suspicious': False,
            'suspicious_findings': [],
            'segments_analyzed': {},
            'total_checks': 0
        }
    
    def analyze_email(self, parsed_email: Dict) -> Dict:
        """
        Analyze parsed email for phishing indicators
        
        Args:
            parsed_email (Dict): Parsed email data from EmailParser
            
        Returns:
            Dict: Analysis results
        """
        self.results = {
            'is_suspicious': False,
            'suspicious_findings': [],
            'segments_analyzed': {},
            'total_checks': 0
        }
        
        # Analyze each rule in the setup file
        for _, rule in self.setup_rules.iterrows():
            start_segment = str(rule['start_segment']).lower().strip()
            end_segment = str(rule['end_segment']).lower().strip()
            suspicious_phrase = str(rule['suspicious_phrase']).strip()
            
            self.results['total_checks'] += 1
            
            # Find the target segment to analyze
            segment_content, segment_info = self._get_segment_content(
                parsed_email, start_segment, end_segment
            )
            
            if segment_content:
                # Add to analyzed segments
                segment_key = f"{start_segment}-{end_segment}"
                self.results['segments_analyzed'][segment_key] = segment_info
                
                # Check for suspicious phrase
                finding = self._check_for_phrase(
                    segment_content, suspicious_phrase, segment_info, start_segment
                )
                
                if finding:
                    self.results['suspicious_findings'].append(finding)
                    self.results['is_suspicious'] = True
        
        return self.results
    
    def _get_segment_content(self, parsed_email: Dict, start_segment: str, end_segment: str) -> tuple:
        """
        Extract content from specified email segment
        
        Args:
            parsed_email (Dict): Parsed email data
            start_segment (str): Start segment identifier (e.g., '<body')
            end_segment (str): End segment identifier (e.g., '</body>')
            
        Returns:
            tuple: (segment_content, segment_info) or (None, None) if not found
        """
        # Handle body segment specially
        if start_segment == '<body' or start_segment == 'body':
            if 'body' in parsed_email['segments']:
                segment_info = parsed_email['segments']['body'].copy()
                return segment_info['content'], segment_info
        
        # Handle other predefined segments
        for segment_name, segment_data in parsed_email['segments'].items():
            if start_segment in segment_name.lower():
                return segment_data['content'], segment_data
        
        # Handle custom segments by searching raw lines
        raw_lines = parsed_email['raw_lines']
        start_line = None
        end_line = None
        
        # Find start and end lines
        for i, line in enumerate(raw_lines):
            if start_segment in line.lower() and start_line is None:
                start_line = i
            if end_segment in line.lower() and start_line is not None:
                end_line = i
                break
        
        if start_line is not None:
            if end_line is None:
                end_line = len(raw_lines) - 1
            
            content = '\n'.join(raw_lines[start_line:end_line + 1])
            segment_info = {
                'start_line': start_line + 1,
                'end_line': end_line + 1,
                'content': content
            }
            return content, segment_info
        
        return None, None
    
    def _check_for_phrase(self, content: str, phrase: str, segment_info: Dict, segment_name: str) -> Dict:
        """
        Check if suspicious phrase exists in content
        
        Args:
            content (str): Content to search
            phrase (str): Phrase to look for
            segment_info (Dict): Information about the segment
            segment_name (str): Name of the segment being checked
            
        Returns:
            Dict: Finding details if phrase found, None otherwise
        """
        # Case-insensitive search
        if phrase.lower() in content.lower():
            # Find the line number where the phrase appears
            lines = content.split('\n')
            phrase_line = None
            context_lines = []
            
            for i, line in enumerate(lines):
                if phrase.lower() in line.lower():
                    phrase_line = segment_info['start_line'] + i
                    
                    # Get context (line with phrase + surrounding lines)
                    start_context = max(0, i - 1)
                    end_context = min(len(lines), i + 2)
                    context_lines = lines[start_context:end_context]
                    break
            
            if phrase_line:
                return {
                    'phrase': phrase,
                    'segment': segment_name,
                    'line_number': phrase_line,
                    'context': '\n'.join(context_lines),
                    'full_segment_content': content
                }
        
        return {}
