import os
import platform
import subprocess
import sys
import datetime
import json
import re
import winreg

class SecurityMonitor:
    def __init__(self, log_dir='C:\\SecurityLogs'):
        """
        Initialize security monitoring setup without external dependencies
        
        Args:
            log_dir (str): Directory to store security log files
        """
        self.log_dir = log_dir
        try:
            os.makedirs(log_dir, exist_ok=True)
        except Exception as e:
            print(f"Error creating log directory: {e}")
        
        # Initialize report structure
        self.report = {
            'timestamp': datetime.datetime.now().isoformat(),
            'hostname': platform.node(),
            'sections': {}
        }
    
    def run_command(self, command):
        """
        Safely run shell commands and capture output
        
        Args:
            command (str): Command to execute
        
        Returns:
            str: Command output or error message  
        """
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
            return result
        except subprocess.CalledProcessError as e:
            return f"Command failed with error: {e.output}"
    
    def analyze_user_accounts(self):
        """
        Analyze Windows user accounts for security insights
        
        Checks:
        1. List of user accounts
        2. Administrative accounts
        3. Account creation dates
        """
        try:
            # Get user accounts
            user_list_cmd = 'net user'
            user_list_output = self.run_command(user_list_cmd)
            
            # Get admin accounts
            admin_cmd = 'net localgroup administrators'
            admin_output = self.run_command(admin_cmd)
            
            # Extract admin users
            admin_users = [line.strip() for line in admin_output.split('\n') 
                           if line and not line.startswith('---') 
                           and line not in ['Administrators:', '']]
            
            self.report['sections']['user_accounts'] = {
                'total_user_accounts': len(re.findall(r'\S+', user_list_output)),
                'admin_accounts': admin_users,
                'recommendation': (
                    'Reduce admin accounts. ' + 
                    f'{len(admin_users)} admin accounts detected.' if len(admin_users) > 2 
                    else 'Admin account count appears appropriate.'
                )
            }
        except Exception as e:
            self.report['sections']['user_accounts'] = {
                'error': f'User account analysis failed: {str(e)}'
            }
    
    def check_running_processes(self):
        """
        Analyze running processes using Windows-native commands
        
        Uses tasklist to gather process information
        """
        try:
            # Get process list with more details
            process_cmd = 'tasklist /V /FO CSV'
            process_output = self.run_command(process_cmd)
            
            # Parse CSV output
            processes = [line.split(',') for line in process_output.split('\n') if line]
            headers = processes[0]
            
            # Top 10 processes by memory usage
            top_processes = sorted(
                processes[1:], 
                key=lambda x: float(x[headers.index('Mem Usage')].replace('"', '').replace(' K', '')) 
                if len(x) > headers.index('Mem Usage') else 0, 
                reverse=True
            )[:10]
            
            self.report['sections']['process_monitor'] = {
                'top_processes': [
                    {
                        'name': p[headers.index('Image Name')].replace('"', ''),
                        'pid': p[headers.index('PID')].replace('"', ''),
                        'memory_usage': p[headers.index('Mem Usage')].replace('"', '')
                    } for p in top_processes
                ],
                'recommendation': 'Review top memory-consuming processes for potential security risks.'
            }
        except Exception as e:
            self.report['sections']['process_monitor'] = {
                'error': f'Process monitoring failed: {str(e)}'
            }
    
    def check_system_services(self):
        """
        Analyze system services for potential security concerns
        
        Checks service status and configurations
        """
        try:
            # List all services
            services_cmd = 'sc queryex'
            services_output = self.run_command(services_cmd)
            
            # Identify potentially risky services
            vulnerable_services_keywords = [
                'remote', 'telnet', 'tftp', 'vnc', 
                'rdp', 'teamviewer', 'rdns'
            ]
            
            vulnerable_services = [
                line for line in services_output.split('\n') 
                if any(keyword in line.lower() for keyword in vulnerable_services_keywords)
            ]
            
            self.report['sections']['system_services'] = {
                'potentially_vulnerable_services': vulnerable_services,
                'recommendation': (
                    'Review and disable unnecessary remote access services. ' +
                    f'{len(vulnerable_services)} potentially risky services detected.'
                )
            }
        except Exception as e:
            self.report['sections']['system_services'] = {
                'error': f'Service analysis failed: {str(e)}'
            }
    
    def check_registry_security(self):
        """
        Check critical Windows registry keys for security configurations
        
        Examines key security-related registry settings
        """
        try:
            registry_checks = {}
            
            # Check Remote Desktop settings
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                r"SYSTEM\CurrentControlSet\Control\Terminal Server") as key:
                rdp_enabled = winreg.QueryValueEx(key, "fDenyTSConnections")[0] == 0
                registry_checks['remote_desktop'] = {
                    'enabled': rdp_enabled,
                    'recommendation': 'Disable Remote Desktop if not required.'
                }
            
            self.report['sections']['registry_security'] = registry_checks
        except Exception as e:
            self.report['sections']['registry_security'] = {
                'error': f'Registry security check failed: {str(e)}'
            }
    
    def generate_security_report(self):
        """
        Generate comprehensive security report in multiple formats
        """
        try:
            # Create log directory if not exists
            os.makedirs(self.log_dir, exist_ok=True)
            
            # Timestamp for unique filename
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # JSON Report
            json_path = os.path.join(self.log_dir, f'security_report_{timestamp}.json')
            with open(json_path, 'w') as f:
                json.dump(self.report, f, indent=4)
            
            # Text Report
            txt_path = os.path.join(self.log_dir, f'security_report_{timestamp}.txt')
            with open(txt_path, 'w') as f:
                f.write("Wonderville Security Monitoring Report\n")
                f.write("=====================================\n\n")
                for section, details in self.report['sections'].items():
                    f.write(f"{section.replace('_', ' ').title()}:\n")
                    f.write(json.dumps(details, indent=2) + "\n\n")
            
            print(f"Security reports generated in {self.log_dir}")
            return json_path, txt_path
        
        except Exception as e:
            print(f"Report generation failed: {e}")
            return None, None
    
    def run_security_scan(self):
        """
        Execute comprehensive security monitoring tasks
        """
        print("Starting security scan...")
        self.analyze_user_accounts()
        self.check_running_processes()
        self.check_system_services()
        self.check_registry_security()
        return self.generate_security_report()

def main():
    monitor = SecurityMonitor()
    monitor.run_security_scan()

if __name__ == "__main__":
    main()