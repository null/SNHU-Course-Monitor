from re import search, DOTALL, IGNORECASE, Match
from requests import Session, Response
from json import load, loads
from os import system, name
from html import unescape

###############################################
#
#
#   CREATED BY: https://www.github.com/null
#   CREATED ON: 10/15/2025
#
#
#   INFO:
#
#       This tool authenticates to Microsoft using SNHU login credentials, then uses that session to log
#       into Brightspace (your course enrollment platform). Once connected, it queries the Brightspace API to
#       retrieve all incomplete/unsubmitted coursework from your PINNED courses and displays the results in the console.
#
#
#   HOW-TO:
#
#       Open the "config.json" file in the directory this file is found in. In this file enter your email address
#       in the email field and password in the password field and then save the file. Once saved you want to path to the directory
#       the "main.py" file is stored in and then run the command "py main.py". This will then run this script and display the
#       course work you have not completed in your PINNED courses found in Brightspace.
#
#
#   EXAMPLE CONFIG.JSON FILE:
#
#       {
#           "login_information": {
#
#               "email": "example_email@123.com",
#               "password": "example_password123"
#
#           }
#       }
#
#
#   PREREQUISITES:
#
#       This tool requires Python 3.10+ to be installed on your device and preferable added as an environment
#       variable to your PATH and to also have the requests module installed. To install the requests module after Python and pip is
#       installed on your device, simply run the command in your command prompt "pip install requests". Once this installation
#       is complete and you followed the HOW-TO guide this should be working correctly.
#
#
#   WARNING:
#
#       This tool may violate SNHU's and/or Brightspace's Terms of Service by 
#       automating authentication and accessing their API in unauthorized ways. 
#
#       Use of this tool could result in:
#
#           - Academic disciplinary action (suspension/expulsion)
#           - Revocation of access to university systems
#           - Legal consequences
#
#       This project is for educational/research purposes to demonstrate API interaction and authentication flows. By using this
#       tool, you assume all risks and responsibilities. The author assumes no liability for any consequences resulting from its use.
#
#
#   USE AT YOUR OWN RISK. 
#
#
#######################################################################################################################################################

class SNHUAuth:
    def __init__(self, email: str, password: str) -> None:
        self.session: Session = Session()
        self.headers: dict = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
        }

        self.email = email
        self.password = password
        
        self.original_request: str = ""
        self.flow_token: str = ""
        self.canary: str = ""
        self.hpgact: str = ""
        self.hpgid: str = ""
        
    def snhu_login(self) -> bool:
        system("cls" if name == "nt" else "clear")
        
        if not self.start_saml_flow():
            return False

        return True
    
    def start_saml_flow(self) -> bool:
        try:
            response: Response = self.session.get(
                "https://learn.snhu.edu/d2l/lp/auth/saml/login",
                headers=self.headers,
                allow_redirects=False
            )

            while response.status_code in [301, 302, 303, 307, 308]:
                redirect_url: str = response.headers.get("Location", "")

                if not redirect_url:
                    break
                
                if "login.microsoftonline.com" in redirect_url and "saml2" in redirect_url:
                    return self.complete_microsoft_auth(redirect_url)
                
                if redirect_url.startswith("/"):
                    redirect_url: str = "https://learn.snhu.edu" + redirect_url
                
                response: Response = self.session.get(
                    redirect_url,
                    headers=self.headers,
                    allow_redirects=False
                )
            
            return True
            
        except:
            return False
    
    def complete_microsoft_auth(self, saml_url: str) -> bool:
        try:
            response: Response = self.session.get(
                saml_url,
                headers=self.headers,
                allow_redirects=False
            )

            for _ in range(10):
                if response.status_code == 200:
                    if "BssoInterrupt" in response.text:
                        config_match: Match = search(r"\$Config\s*=\s*({.+?});", response.text, DOTALL)

                        if config_match:
                            config: dict = loads(config_match.group(1))
                            url_post: str = config.get("urlPost", "")
                            
                            if url_post:
                                if not url_post.startswith("http"):
                                    url_post: str = "https://login.microsoftonline.com" + url_post

                                response: Response = self.session.get(
                                    url_post,
                                    headers=self.headers,
                                    allow_redirects=False
                                )
                                continue
                    
                    elif "ConvergedSignIn" in response.text:
                        break
                    
                    return False

                elif response.status_code in [301, 302, 303, 307, 308]:
                    redirect_url: str = response.headers.get("Location", "")

                    if not redirect_url:
                        return False
                    
                    if not redirect_url.startswith("http"):
                        if redirect_url.startswith("/"):
                            redirect_url: str = "https://login.microsoftonline.com" + redirect_url

                        else:
                            redirect_url: str = "https://login.microsoftonline.com/" + redirect_url
                    
                    response: Response = self.session.get(
                        redirect_url,
                        headers=self.headers,
                        allow_redirects=False
                    )
                
                else:
                    return False

            if not self.extract_tokens(response.text):
                return False

            if not self.fetch_credential_type():
                return False
            
            return self.submit_password_saml()
            
        except:
            return False
    
    def extract_tokens(self, html: str) -> bool:
        try:
            sft: Match = search(r'"sFT"\s*:\s*"([^"]+)"', html)
            sctx: Match = search(r'"sCtx"\s*:\s*"([^"]+)"', html)
            canary: Match = search(r'"canary"\s*:\s*"([^"]+)"', html)
            hpgact: Match = search(r'"hpgact"\s*:\s*(\d+)', html)
            hpgid: Match = search(r'"hpgid"\s*:\s*(\d+)', html)
            
            if not sft or not sctx:
                return False
            
            self.flow_token: str = sft.group(1)
            self.original_request: str = sctx.group(1)
            self.canary: str = canary.group(1) if canary else ""
            self.hpgid: str = hpgid.group(1) if hpgid else "1104"
            self.hpgact: str = hpgact.group(1) if hpgact else "1800"

            return True

        except:
            return False
    
    def fetch_credential_type(self) -> bool:

        self.headers["Content-Type"] = "application/json"
        self.headers["canary"] = self.canary
        self.headers["hpgact"] = self.hpgact
        self.headers["hpgid"] = self.hpgid
        
        payload: dict = {
            "originalRequest": self.original_request,
            "flowToken": self.flow_token,
            "username": self.email,
        }
        
        response: Response = self.session.post(
            "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US",
            headers=self.headers,
            json=payload
        )

        self.headers.pop("Content-Type", None)
        self.headers.pop("canary", None)
        self.headers.pop("hpgact", None)
        self.headers.pop("hpgid", None)
        
        if response.status_code == 200:
            data: dict = response.json()

            if "FlowToken" in data:
                self.flow_token: str = data["FlowToken"]
                return True
        
        return False
    
    def submit_password_saml(self) -> bool:
        payload: dict = {
            "ctx": self.original_request,
            "flowToken": self.flow_token,
            "passwd": self.password,
            "loginfmt": self.email,
            "canary": self.canary,
            "login": self.email
        }
        
        response: Response = self.session.post(
            "https://login.microsoftonline.com/common/login",
            headers=self.headers,
            data=payload,
            allow_redirects=False
        )
        
        for _ in range(20):
            if response.status_code in [302, 301, 303, 307, 308]:
                redirect_url: str = response.headers.get("Location", "")

                if not redirect_url:
                    break
                
                if "learn.snhu.edu" in redirect_url and "samlLogin" in redirect_url:
                    response: Response = self.session.get(
                        redirect_url,
                        headers=self.headers,
                        allow_redirects=True
                    )
                    
                    if "d2lSessionVal" in self.session.cookies:
                        return True

                    else:
                        return self.handle_saml_response_form(response.text)

                if response.status_code == 200 and "BssoInterrupt" in response.text:
                    return self.handle_bsso_for_saml(response.text)
                
                if redirect_url.startswith("/"):
                    redirect_url: str = "https://login.microsoftonline.com" + redirect_url
                
                response: Response = self.session.get(
                    redirect_url,
                    headers=self.headers,
                    allow_redirects=False
                )
            
            elif response.status_code == 200:
                if "d2lSessionVal" in self.session.cookies:
                    return True

                elif "BssoInterrupt" in response.text:
                    return self.handle_bsso_for_saml(response.text)

                elif "SAMLResponse" in response.text or "samlLogin" in response.text:
                    return self.handle_saml_response_form(response.text)

                break
        
        return False
    
    def handle_bsso_for_saml(self, html: str) -> bool:
        try:
            config_match: Match = search(r'\$Config\s*=\s*({.+?});', html, DOTALL)

            if not config_match:
                return False
            
            config: dict = loads(config_match.group(1))
            form_data: dict = config.get("oPostParams", {})
            url_post: str = config.get("urlPost", "")

            if not url_post or not form_data:
                return False
            
            if not url_post.startswith("http"):
                url_post: str = "https://login.microsoftonline.com" + url_post
            
            response: Response = self.session.post(
                url_post,
                data=form_data,
                headers=self.headers,
                allow_redirects=True
            )
            
            if "d2lSessionVal" in self.session.cookies:
                return True

            elif "SAMLResponse" in response.text or "samlLogin" in response.text:
                return self.handle_saml_response_form(response.text)
            
            return False

        except:
            return False
    
    def handle_saml_response_form(self, html: str) -> bool:
        try:
            form: Match = search(r'<form[^>]*action=["\']([^"\']+)["\']', html, IGNORECASE)
            if not form:
                return False

            action: str = form.group(1)
            saml_match: Match = search(r'name=["\']SAMLResponse["\'][^>]*value=["\']([^"\']+)["\']', html, IGNORECASE)
            if not saml_match:
                return False
            
            saml_response: str = unescape(saml_match.group(1))

            if not action.startswith("http"):
                action: str = "https://learn.snhu.edu" + action

            response: Response = self.session.post(
                action,
                data={"SAMLResponse": saml_response},
                headers=self.headers,
                allow_redirects=True
            )
            
            return "d2lSessionVal" in self.session.cookies
            
        except:
            return False

class DisplayCourseContent:
    def __init__(self, session: Session = None):
        self.session: Session = session if session else Session()
        self.headers: dict = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
        }

    def fetch_course_id_and_name(self) -> dict:
        course_dict: dict = {}

        response: Response = self.session.get(
            "https://learn.snhu.edu/d2l/home"
        )

        find_xsrf: Match = search(r"localStorage\.setItem\('XSRF\.Token','([^']+)'\)", response.text)
        xsrf_token: str = find_xsrf.group(1) if find_xsrf else None
        
        find_user_id: Match = search(r"localStorage\.setItem\('Session\.UserId','([^']+)'\)", response.text)
        user_id: str = find_user_id.group(1) if find_xsrf else None

        bearer_response: Response = self.session.post(
            "https://learn.snhu.edu/d2l/lp/auth/oauth2/token",
            headers={"x-csrf-token": xsrf_token },
            data={"scope": "*:*:*"}
        )

        course_response: Response = self.session.get(
            f"https://fb3533a3-c42b-4ba8-90a4-216b16f5ef12.enrollments.api.brightspace.com/users/{user_id}",
            headers={ "Authorization": f"Bearer {bearer_response.json()['access_token']}" }
        )
        
        for i in course_response.json()["entities"]:
            if "pinned" in i["class"]:

                course_id_response: Response = self.session.get(
                    i["href"],
                    headers={ "Authorization": f"Bearer {bearer_response.json()['access_token']}" }
                )
                course_id: str = search(r"/(\d+)\?", course_id_response.json()["links"][1]["href"]).group(1)

                course_name_response: Response = self.session.get(
                    f"https://fb3533a3-c42b-4ba8-90a4-216b16f5ef12.organizations.api.brightspace.com/" + course_id + "?localeId=1",
                    headers={ "Authorization": f"Bearer {bearer_response.json()['access_token']}" }
                )
                course_name: str = course_name_response.json()["properties"]["name"][0:7].replace("-", "")
                course_dict[course_name] = course_id

        return course_dict

    def sort_content(self, course_dict: dict) -> None:
        lessons: list = []

        for course_name, course_id in course_dict.items():
            try:
                course_response: Response = self.session.get(
                    f"https://learn.snhu.edu/d2l/api/le/1.75/{course_id}/content/completions/mycount/?level=3",
                    headers=self.headers
                )
                
                if course_response.status_code != 200:
                    continue
                
                course_objects: list = course_response.json()["Objects"]

                for item in course_objects:
                    title: str = item.get("Title", "")
                    completed: bool = item.get("CompletedItems", 0) == 1
                    lessons.append((title, completed, course_name))
                    
            except:
                continue

        if not lessons:
            return

        weeks: dict = {}
        unknown: list = []
        
        for title, completed, course in lessons:
            if completed:
                continue

            if "(Non-graded)" not in title:
                if "-" in title:
                    prefix: str = title.split("-", 1)[0].strip()

                    if prefix.isdigit():
                        week_num: int = int(prefix)

                        if week_num not in weeks:
                            weeks[week_num] = []
                        weeks[week_num].append((title, course))

                    else:
                        unknown.append((title, course))

                else:
                    unknown.append((title, course))

        for week_num in sorted(weeks.keys()):
            print(f"\nWeek {week_num}:")

            for title, course in weeks[week_num]:
                print(f"  {title} | {course}")

        if unknown:
            print(f"\nUnknown:")

            for title, course in unknown:
                print(f"  {title} | {course}")

def run_script() -> None:
    with open("config.json") as cf:
        config_file: dict = load(cf)
    
    auth = SNHUAuth(config_file["login_information"]["email"], config_file["login_information"]["password"])
    if not auth.snhu_login():
        print("Authentication failed")
        exit(1)

    display = DisplayCourseContent(session=auth.session)
    courses: dict = display.fetch_course_id_and_name()
    display.sort_content(courses)

if __name__ == "__main__":
    run_script()