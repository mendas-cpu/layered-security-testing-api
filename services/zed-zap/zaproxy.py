from pprint import pprint
from zapv2 import ZAPv2
from dotenv import load_dotenv
import time
import os

class ZapScanner:
    def __init__(self, target, api_key):
        self.scan_id = None
        self.target = target
        self.api_key = api_key
        self.zap = ZAPv2(apikey=self.api_key)

    #ajax spider based method to explore the app for any js populated content or xss attacks possibility
    def exploring_app(self):
        if self.api_key is None:
            print("No API key provided")
            return

        self.scan_id = self.zap.ajaxSpider.scan(self.target)
        start_time = time.time()
        while self.zap.ajaxSpider.status != 'stopped':
            if time.time() - start_time > 120:  # 2 minute timeout
                self.zap.ajaxSpider.stop()
                print("Ajax spider timed out, stopping...")
                break
            print('Ajax Spider status: ' + self.zap.ajaxSpider.status)
            time.sleep(2)

        print("Ajax spider completed")

    #active scanning
    def active_scan(self):
        if self.api_key is None:
            print("No API key provided")
            return
        self.scan_id = self.zap.ascan.scan(self.target)
        while int(self.zap.ascan.status(self.scan_id)) < 100:
            print('Scan progress %: {}'.format(self.zap.ascan.status(self.scan_id)))
            time.sleep(5)
        print("Active scan completed")
        return self.zap.alert.alerts(baseurl=self.target, start=0, count=5000)

    #returning the alerts dict after initiating exploration and active scanning
    def results(self):
        self.exploring_app()
        alert_dict = {}
        alert_count = 0
        st = 0
        pg = 5000
        blacklist = [1, 2]
        alerts = self.zap.alert.alerts(baseurl=self.target, start=st, count=pg)

        while len(alerts) > 0:
            print('Reading {} alerts from {}'.format(pg, st))
            for alert in alerts:
                plugin_id = alert.get('pluginId')
                if plugin_id in blacklist:
                    continue
                if alert.get('risk') == 'Informational':
                    continue
                alert_dict[alert_count] = {
                    "risk": alert.get('risk'),
                    "name": alert.get('name'),
                    "url": alert.get('url'),
                    "description": alert.get('description'),
                    "solution": alert.get('solution')
                }
                alert_count += 1
            st += pg
            alerts = self.zap.alert.alerts(baseurl=self.target, start=st, count=pg)

        return alert_dict
load_dotenv()
target = "https://public-firing-range.appspot.com"
api_key = os.getenv("ZAP_KEY")
ZapScanner = ZapScanner(target, api_key)
pprint(ZapScanner.results())