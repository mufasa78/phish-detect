import email
import email.message
import re
from typing import Dict, List, Tuple, Optional

class EmailParser:
    """Parser for .eml email files"""
    
    def __init__(self):
        self.email_lines = []
        self.parsed_data = {}
    
    def parse_email(self, email_content: str) -> Dict:
        """
        Parse email content and extract different segments
        
        Args:
            email_content (str): Raw email content from .eml file
            
        Returns:
            Dict: Parsed email data with segments and metadata
        """
        self.email_lines = email_content.split('\n')
        
        # Parse using email library
        msg = email.message_from_string(email_content)
        
        # Extract basic headers
        headers = {
            'from': msg.get('From', ''),
            'to': msg.get('To', ''),
            'subject': msg.get('Subject', ''),
            'date': msg.get('Date', ''),
            'message_id': msg.get('Message-ID', '')
        }
        
        # Find different segments in the raw email
        segments = self._extract_segments()
        
        # Extract body content
        body_content = self._extract_body_content(msg)
        
        return {
            'headers': headers,
            'segments': segments,
            'body_content': body_content,
            'raw_lines': self.email_lines,
            'total_lines': len(self.email_lines)
        }
    
    def _extract_segments(self) -> Dict:
        """Extract different segments from the email based on patterns"""
        segments = {}
        
        # Find body segment (HTML content)
        body_start, body_end = self._find_segment_boundaries('<body', '</body>')
        if body_start is not None and body_end is not None:
            segments['body'] = {
                'start_line': body_start + 1,  # 1-indexed
                'end_line': body_end + 1,
                'content': '\n'.join(self.email_lines[body_start:body_end + 1])
            }
        
        # Find other common segments
        segments.update(self._find_header_segments())
        
        return segments
    
    def _find_segment_boundaries(self, start_pattern: str, end_pattern: str) -> Tuple[Optional[int], Optional[int]]:
        """Find start and end line numbers for a segment"""
        start_line = None
        end_line = None
        
        for i, line in enumerate(self.email_lines):
            if start_pattern.lower() in line.lower() and start_line is None:
                start_line = i
            if end_pattern.lower() in line.lower() and start_line is not None:
                end_line = i
                break
        
        return start_line, end_line
    
    def _find_header_segments(self) -> Dict:
        """Find common email header segments"""
        segments = {}
        
        # Common headers to extract as segments
        header_patterns = {
            'x-ms-exchange-crosstenant-id': r'x-ms-exchange-crosstenant-id',
            'x-ms-exchange-crosstenant-userprincipalname': r'x-ms-exchange-crosstenant-userprincipalname',
            'received': r'^received:',
            'authentication-results': r'authentication-results:'
        }
        
        for segment_name, pattern in header_patterns.items():
            for i, line in enumerate(self.email_lines):
                if re.search(pattern, line, re.IGNORECASE):
                    # For multi-line headers, find the complete segment
                    start_line = i
                    end_line = i
                    
                    # Continue until next header or empty line
                    for j in range(i + 1, len(self.email_lines)):
                        if (self.email_lines[j].strip() == '' or 
                            (not self.email_lines[j].startswith(' ') and 
                             not self.email_lines[j].startswith('\t') and 
                             ':' in self.email_lines[j])):
                            break
                        end_line = j
                    
                    segments[segment_name] = {
                        'start_line': start_line + 1,  # 1-indexed
                        'end_line': end_line + 1,
                        'content': '\n'.join(self.email_lines[start_line:end_line + 1])
                    }
                    break  # Only find first occurrence
        
        return segments
    
    def _extract_body_content(self, msg: email.message.Message) -> str:
        """Extract body content from email message"""
        body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain" or content_type == "text/html":
                    charset = part.get_content_charset() or 'utf-8'
                    try:
                        payload = part.get_payload(decode=True)
                        if isinstance(payload, bytes):
                            body += payload.decode(charset, errors='ignore')
                        else:
                            body += str(payload)
                    except:
                        body += str(part.get_payload())
        else:
            charset = msg.get_content_charset() or 'utf-8'
            try:
                payload = msg.get_payload(decode=True)
                if isinstance(payload, bytes):
                    body = payload.decode(charset, errors='ignore')
                else:
                    body = str(payload)
            except:
                body = str(msg.get_payload())
        
        return body
