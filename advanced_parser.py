import re
import email
from email.message import Message
from typing import Dict, List, Optional, Tuple, Set, Union
from bs4 import BeautifulSoup, Tag
from bs4.element import NavigableString, PageElement
from dataclasses import dataclass
from enum import Enum


class SegmentType(Enum):
    """Types of email segments for advanced processing"""
    SINGLE_LINE = "single_line"
    MULTI_LINE = "multi_line" 
    HTML = "html"
    HTML_ATTRIBUTE = "html_attribute"
    URL = "url"
    ENCODED = "encoded"


@dataclass
class AdvancedSegment:
    """Enhanced segment representation with advanced metadata"""
    name: str
    content: str
    segment_type: SegmentType
    start_line: int
    end_line: int
    html_elements: Optional[List[Dict]] = None
    urls: Optional[List[str]] = None
    attributes: Optional[Dict] = None
    suspicious_score: float = 0.0


class AdvancedEmailParser:
    """Advanced email parser with HTML processing and multi-line segment detection"""
    
    def __init__(self):
        self.email_lines = []
        self.html_content = ""
        self.soup = None
        
    def parse_email_advanced(self, email_content: str) -> Dict:
        """
        Advanced email parsing with HTML processing and enhanced segment detection
        
        Args:
            email_content (str): Raw email content
            
        Returns:
            Dict: Enhanced parsed email data with advanced segments
        """
        self.email_lines = email_content.split('\n')
        
        # Parse with standard email library
        msg = email.message_from_string(email_content)
        
        # Extract headers with advanced processing
        headers = self._extract_advanced_headers(msg)
        
        # Extract and parse HTML content
        body_content, html_content = self._extract_advanced_body_content(msg)
        self.html_content = html_content
        
        # Parse HTML with BeautifulSoup if available
        if html_content:
            try:
                self.soup = BeautifulSoup(html_content, 'lxml')
            except:
                self.soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract advanced segments
        advanced_segments = self._extract_advanced_segments()
        
        # Extract URLs from email content
        urls = self._extract_urls()
        
        # Analyze HTML structure
        html_analysis = self._analyze_html_structure()
        
        return {
            'headers': headers,
            'segments': advanced_segments,
            'body_content': body_content,
            'html_content': html_content,
            'urls': urls,
            'html_analysis': html_analysis,
            'raw_lines': self.email_lines,
            'total_lines': len(self.email_lines),
            'advanced_features': True
        }
    
    def _extract_advanced_headers(self, msg: Message) -> Dict:
        """Extract headers with advanced processing for suspicious patterns"""
        headers = {}
        
        # Basic headers
        basic_headers = ['From', 'To', 'Subject', 'Date', 'Message-ID', 'Reply-To']
        for header in basic_headers:
            headers[header.lower()] = msg.get(header, '')
        
        # Advanced security headers
        security_headers = [
            'Authentication-Results', 'DKIM-Signature', 'SPF', 'DMARC',
            'X-Spam-Score', 'X-Spam-Status', 'X-Phishing-Score',
            'Received-SPF', 'ARC-Authentication-Results'
        ]
        for header in security_headers:
            value = msg.get(header, '')
            if value:
                headers[header.lower()] = value
        
        # Exchange/Outlook specific headers
        exchange_headers = [
            'X-MS-Exchange-CrossTenant-Id', 'X-MS-Exchange-CrossTenant-UserPrincipalName',
            'X-MS-Exchange-Organization-AuthSource', 'X-Forefront-Antispam-Report'
        ]
        for header in exchange_headers:
            value = msg.get(header, '')
            if value:
                headers[header.lower()] = value
        
        # Extract all Received headers (can be multiple)
        received_headers = []
        for received in msg.get_all('Received') or []:
            received_headers.append(received)
        if received_headers:
            headers['received_chain'] = received_headers
        
        return headers
    
    def _extract_advanced_body_content(self, msg: Message) -> Tuple[str, str]:
        """Extract both plain text and HTML content separately"""
        plain_body = ""
        html_body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                charset = part.get_content_charset() or 'utf-8'
                
                try:
                    payload = part.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        content = payload.decode(charset, errors='ignore')
                    else:
                        content = str(payload)
                    
                    if content_type == "text/plain":
                        plain_body += content
                    elif content_type == "text/html":
                        html_body += content
                        
                except Exception:
                    continue
        else:
            charset = msg.get_content_charset() or 'utf-8'
            try:
                payload = msg.get_payload(decode=True)
                if isinstance(payload, bytes):
                    content = payload.decode(charset, errors='ignore')
                else:
                    content = str(payload)
                
                content_type = msg.get_content_type()
                if content_type == "text/html":
                    html_body = content
                else:
                    plain_body = content
                    
            except Exception:
                pass
        
        # If no plain text, try to extract from HTML
        if not plain_body and html_body:
            try:
                soup = BeautifulSoup(html_body, 'html.parser')
                plain_body = soup.get_text()
            except:
                plain_body = html_body
        
        return plain_body, html_body
    
    def _extract_advanced_segments(self) -> Dict[str, AdvancedSegment]:
        """Extract advanced segments with type detection and enhanced processing"""
        segments = {}
        
        # HTML segments
        if self.soup:
            html_segments = self._extract_html_segments()
            segments.update(html_segments)
        
        # Multi-line header segments
        header_segments = self._extract_multiline_header_segments()
        segments.update(header_segments)
        
        # URL segments
        url_segments = self._extract_url_segments()
        segments.update(url_segments)
        
        # Encoded content segments
        encoded_segments = self._extract_encoded_segments()
        segments.update(encoded_segments)
        
        return segments
    
    def _extract_html_segments(self) -> Dict[str, AdvancedSegment]:
        """Extract and analyze HTML segments"""
        segments = {}
        
        if not self.soup:
            return segments
        
        # Extract different HTML elements
        html_elements = {
            'links': self.soup.find_all('a'),
            'images': self.soup.find_all('img'),
            'scripts': self.soup.find_all('script'),
            'forms': self.soup.find_all('form'),
            'iframes': self.soup.find_all('iframe'),
            'divs': self.soup.find_all('div', class_=True),
            'spans': self.soup.find_all('span', style=True)
        }
        
        for element_type, elements in html_elements.items():
            if elements:
                for i, element in enumerate(elements):
                    # Only process Tag elements, skip NavigableString and other types
                    if not isinstance(element, Tag):
                        continue
                        
                    segment_name = f"html_{element_type}_{i+1}"
                    
                    # Extract relevant attributes
                    attrs = {}
                    if element_type == 'links':
                        href = element.get('href', '')
                        href_str = str(href) if href else ''
                        attrs = {'href': href_str, 'text': element.get_text().strip()}
                    elif element_type == 'images':
                        src = element.get('src', '')
                        alt = element.get('alt', '')
                        attrs = {'src': str(src) if src else '', 'alt': str(alt) if alt else ''}
                    elif element_type == 'forms':
                        action = element.get('action', '')
                        method = element.get('method', '')
                        attrs = {'action': str(action) if action else '', 'method': str(method) if method else ''}
                    elif element_type == 'iframes':
                        src = element.get('src', '')
                        width = element.get('width', '')
                        attrs = {'src': str(src) if src else '', 'width': str(width) if width else ''}
                    
                    segments[segment_name] = AdvancedSegment(
                        name=segment_name,
                        content=str(element),
                        segment_type=SegmentType.HTML,
                        start_line=1,  # HTML parsing doesn't preserve line numbers
                        end_line=1,
                        html_elements=[{'tag': element.name, 'attrs': element.attrs}],
                        attributes=attrs,
                        suspicious_score=self._calculate_html_suspicion_score(element, element_type)
                    )
        
        return segments
    
    def _extract_multiline_header_segments(self) -> Dict[str, AdvancedSegment]:
        """Extract multi-line header segments with enhanced detection"""
        segments = {}
        
        # Enhanced header patterns for multi-line detection
        multiline_patterns = {
            'authentication_results': r'authentication-results:',
            'received': r'^received:',
            'dkim_signature': r'dkim-signature:',
            'arc_authentication': r'arc-authentication-results:',
            'x_spam_report': r'x-.*spam.*:',
            'content_type': r'content-type:',
            'mime_boundary': r'boundary='
        }
        
        for segment_name, pattern in multiline_patterns.items():
            segments.update(self._find_multiline_segment(segment_name, pattern))
        
        return segments
    
    def _find_multiline_segment(self, name: str, pattern: str) -> Dict[str, AdvancedSegment]:
        """Find multi-line segments based on pattern"""
        segments = {}
        found_segments = 0
        
        for i, line in enumerate(self.email_lines):
            if re.search(pattern, line, re.IGNORECASE):
                start_line = i
                end_line = i
                content_lines = [line]
                
                # Continue collecting lines for multi-line headers
                for j in range(i + 1, len(self.email_lines)):
                    next_line = self.email_lines[j]
                    
                    # Check if this is a continuation line
                    if (next_line.startswith(' ') or next_line.startswith('\t') or
                        (next_line.strip() and not ':' in next_line and 
                         not next_line.strip().startswith('--'))):
                        content_lines.append(next_line)
                        end_line = j
                    else:
                        break
                
                # Create advanced segment
                segment_key = f"{name}_{found_segments + 1}" if found_segments > 0 else name
                segments[segment_key] = AdvancedSegment(
                    name=segment_key,
                    content='\n'.join(content_lines),
                    segment_type=SegmentType.MULTI_LINE if len(content_lines) > 1 else SegmentType.SINGLE_LINE,
                    start_line=start_line + 1,
                    end_line=end_line + 1,
                    suspicious_score=self._calculate_header_suspicion_score('\n'.join(content_lines))
                )
                
                found_segments += 1
        
        return segments
    
    def _extract_url_segments(self) -> Dict[str, AdvancedSegment]:
        """Extract URL segments from email content"""
        segments = {}
        urls = self._extract_urls()
        
        for i, url in enumerate(urls):
            segment_name = f"url_{i+1}"
            
            # Find the line containing this URL
            line_num = 1
            for j, line in enumerate(self.email_lines):
                if url in line:
                    line_num = j + 1
                    break
            
            segments[segment_name] = AdvancedSegment(
                name=segment_name,
                content=url,
                segment_type=SegmentType.URL,
                start_line=line_num,
                end_line=line_num,
                urls=[url],
                suspicious_score=self._calculate_url_suspicion_score(url)
            )
        
        return segments
    
    def _extract_encoded_segments(self) -> Dict[str, AdvancedSegment]:
        """Extract base64 and other encoded segments"""
        segments = {}
        
        # Look for base64 encoded content
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        encoded_segments = 0
        
        for i, line in enumerate(self.email_lines):
            matches = re.findall(base64_pattern, line)
            for match in matches:
                if len(match) > 50:  # Only consider substantial encoded strings
                    segment_name = f"encoded_{encoded_segments + 1}"
                    segments[segment_name] = AdvancedSegment(
                        name=segment_name,
                        content=match,
                        segment_type=SegmentType.ENCODED,
                        start_line=i + 1,
                        end_line=i + 1,
                        suspicious_score=0.3  # Encoded content is somewhat suspicious
                    )
                    encoded_segments += 1
        
        return segments
    
    def _extract_urls(self) -> List[str]:
        """Extract all URLs from email content"""
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\']*)?'
        urls = []
        
        # Extract from raw text
        content = '\n'.join(self.email_lines)
        urls.extend(re.findall(url_pattern, content))
        
        # Extract from HTML if available
        if self.soup:
            for link in self.soup.find_all('a', href=True):
                if isinstance(link, Tag):
                    href = link.get('href', '')
                    href_str = str(href) if href else ''
                    if href_str.startswith(('http://', 'https://', 'www.')):
                        urls.append(href_str)
        
        return list(set(urls))  # Remove duplicates
    
    def _analyze_html_structure(self) -> Dict:
        """Analyze HTML structure for suspicious patterns"""
        if not self.soup:
            return {}
        
        analysis = {
            'has_forms': len(self.soup.find_all('form')) > 0,
            'has_scripts': len(self.soup.find_all('script')) > 0,
            'has_iframes': len(self.soup.find_all('iframe')) > 0,
            'external_links': 0,
            'suspicious_attributes': [],
            'hidden_elements': 0,
            'total_links': len(self.soup.find_all('a')),
            'images_count': len(self.soup.find_all('img'))
        }
        
        # Analyze links
        for link in self.soup.find_all('a', href=True):
            if isinstance(link, Tag):
                href = link.get('href', '')
                href_str = str(href) if href else ''
                if href_str.startswith(('http://', 'https://')) and 'example.com' not in href_str:
                    analysis['external_links'] += 1
        
        # Look for suspicious attributes
        suspicious_attrs = ['onclick', 'onload', 'onerror', 'onmouseover']
        for element in self.soup.find_all():
            if isinstance(element, Tag):
                for attr in suspicious_attrs:
                    attr_value = element.get(attr)
                    if attr_value:
                        analysis['suspicious_attributes'].append({
                            'element': element.name,
                            'attribute': attr,
                            'value': str(attr_value)
                        })
        
        # Count hidden elements
        for element in self.soup.find_all(['div', 'span', 'p']):
            if isinstance(element, Tag):
                style = element.get('style', '')
                style_str = str(style) if style else ''
                if 'display:none' in style_str.replace(' ', '') or 'visibility:hidden' in style_str.replace(' ', ''):
                    analysis['hidden_elements'] += 1
        
        return analysis
    
    def _calculate_html_suspicion_score(self, element: Tag, element_type: str) -> float:
        """Calculate suspicion score for HTML elements"""
        score = 0.0
        
        if element_type == 'links':
            href = element.get('href', '')
            href_str = str(href) if href else ''
            if href_str:
                # Suspicious URL patterns
                if re.search(r'bit\.ly|tinyurl|goo\.gl|t\.co', href_str):
                    score += 0.3
                if re.search(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', href_str):  # IP address
                    score += 0.5
                if len(href_str) > 100:  # Very long URLs
                    score += 0.2
        
        elif element_type == 'forms':
            action = element.get('action', '')
            action_str = str(action) if action else ''
            if action_str and not action_str.startswith(('https://', 'mailto:')):
                score += 0.4
        
        elif element_type == 'scripts':
            score += 0.3  # Scripts are inherently more suspicious
            
        elif element_type == 'iframes':
            score += 0.4  # iframes can be used for malicious purposes
        
        return min(score, 1.0)
    
    def _calculate_header_suspicion_score(self, header_content: str) -> float:
        """Calculate suspicion score for header content"""
        score = 0.0
        
        # Check for authentication failures
        if re.search(r'fail|none|softfail', header_content, re.IGNORECASE):
            score += 0.3
        
        # Check for suspicious domains
        if re.search(r'suspicious|phishing|spam', header_content, re.IGNORECASE):
            score += 0.5
        
        return min(score, 1.0)
    
    def _calculate_url_suspicion_score(self, url: str) -> float:
        """Calculate suspicion score for URLs"""
        score = 0.0
        
        # URL shorteners
        if re.search(r'bit\.ly|tinyurl|goo\.gl|t\.co|short', url):
            score += 0.4
        
        # IP addresses instead of domains
        if re.search(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', url):
            score += 0.6
        
        # Suspicious TLDs
        if re.search(r'\.(tk|ml|ga|cf|click)/', url):
            score += 0.3
        
        # Very long URLs (potential obfuscation)
        if len(url) > 100:
            score += 0.2
        
        # Suspicious keywords
        if re.search(r'secure|verify|account|login|update|confirm', url, re.IGNORECASE):
            score += 0.3
        
        return min(score, 1.0)