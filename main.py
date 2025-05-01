import os
import platform
import socket
import subprocess
import sys
import threading
from io import BytesIO

import pycountry
from bs4 import BeautifulSoup
import dearpygui.dearpygui as dpg
import psutil
import requests
from filedialogs import open_file_dialog, save_file_dialog


def get_base_path():
    try:
        if getattr(sys, "frozen", False):
            return os.path.dirname(sys.executable)
        else:
            return os.path.dirname(os.path.abspath(__file__))
    except Exception as e:
        raise e


def terminate_process(process_name):
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if process_name.lower() in proc.info["name"].lower():
                proc.terminate()
                proc.wait(3)
                return f"Terminated process {proc.info['name']} with PID {proc.info['pid']}\n"
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass


def start_thread(target, *args):
    try:
        thread = threading.Thread(target=target, args=args)
        thread.daemon = True
        thread.start()
        return thread
    except Exception as e:
        raise e


def find_available_ports(start_port, end_port, skip_ports=[]):
    available_ports = []

    for port in range(start_port, end_port + 1):
        if port in skip_ports:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            try:
                s.bind(("0.0.0.0", port))
                available_ports.append(port)
            except socket.error:
                continue

    return available_ports


def save_item_to_file(item):
    try:
        content = dpg.get_value(item)
        save_path = save_file_dialog()
        if save_path:
            with open(save_path, "w") as f:
                f.write(content)
    except Exception as e:
        raise e


def open_file_to_item(item):
    try:
        open_path = open_file_dialog()
        if open_path:
            with open(open_path, "r") as f:
                content = f.read()
            dpg.set_value(item, content)
    except Exception as e:
        raise e


def execute_source(shell):
    try:
        source = dpg.get_value(shell)
        exec(source)
    except Exception as e:
        raise e


def execute_command(command):
    try:
        return subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
    except Exception as e:
        raise e


def exit():
    input("Press any key to continue... ")
    sys.exit(1)


def view_ip_info():
    ip_address = dpg.get_value("IP address Input")
    if not ip_address:
        dpg.set_value(
            "Popup text",
            "You will see your own IP address information!",
        )
        dpg.show_item("Popup window")

    try:
        ip_info = get_ip_info(ip_address)
    except Exception as e:
        dpg.set_value("Popup text", e)
        dpg.show_item("Popup window")
        return

    readable_data = (
        f"IP: {ip_info['IP']}\n"
        f"City: {ip_info['City']}\n"
        f"Region: {ip_info['Region']}\n"
        f"Country: {ip_info['Country']}\n"
        f"Location: {ip_info['Location']}\n"
        f"Org: {ip_info['Org']}\n"
        f"Hostname: {ip_info['Hostname'] if ip_info['Hostname'] else 'N/A'}\n"
        f"Postal Code: {ip_info['Postal Code']}"
    )

    dpg.set_value("IP address output", readable_data)


def get_ip_info(ip_address):
    url = f"http://ipinfo.io/{ip_address}/json"

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        ip_info = {
            "IP": data.get("ip"),
            "City": data.get("city"),
            "Region": data.get("region"),
            "Country": data.get("country"),
            "Location": data.get("loc"),
            "Org": data.get("org"),
            "Hostname": data.get("hostname"),
            "Postal Code": data.get("postal"),
        }

        return ip_info
    except requests.exceptions.RequestException as e:
        raise RuntimeError(e)


class Tor:
    base_path = get_base_path()

    config_file = os.path.join(base_path, "tor-14.0.5", "torrc")
    executable = os.path.join(base_path, "tor-14.0.5", "tor.exe")
    geoip = os.path.join(base_path, "tor-14.0.5", "data", "geoip")
    geoip6 = os.path.join(base_path, "tor-14.0.5", "data", "geoip6")

    def run():
        try:
            dpg.disable_item("Start Tor button")
            Tor.stop()

            num_ports = dpg.get_value("Proxy count")
            if num_ports < 1 or num_ports > 65535:
                dpg.set_value("Popup text", "Proxy count must be between 1 and 65535")
                dpg.show_item("Popup window")
                return
            else:
                start_port = 65535
                end_port = 65535 - num_ports + 1
                available_ports = find_available_ports(end_port, start_port)
                if len(available_ports) > 0:
                    dpg.set_value(
                        "Tor logs",
                        f"{dpg.get_value('Tor logs')}[*] {len(available_ports)} available port found\n",
                    )
                    dpg.configure_item(
                        "Proxy list",
                        items=[
                            f"socks5h://127.0.0.1:{port}" for port in available_ports
                        ],
                    )
                else:
                    dpg.set_value(
                        "Tor logs",
                        f"{dpg.get_value('Tor logs')}[-] None available port found\n",
                    )
                    return

            options = [
                f"GeoIPFile {Tor.geoip}",
                f"GeoIPv6File {Tor.geoip6}",
                "ExitNodes {us},{ca},{de}",
                "DisableNetwork 0",
                "AvoidDiskWrites 1",
                "DNSPort auto",
            ] + [f"SocksPort {port}" for port in available_ports]
            Tor.configure(options)

            dpg.set_value(
                "Tor logs", f"{dpg.get_value('Tor logs')}[*] Tor configured\n"
            )

            dpg.set_value(
                "Tor logs", f"{dpg.get_value('Tor logs')}[*] Tor starting...\n"
            )
            Tor.start()
            
            dpg.enable_item("Start Tor button")
        except Exception as e:
            dpg.set_value("Tor logs", f"{dpg.get_value('Tor logs')}[-] {e}\n")

    def print_output(process):
        try:
            for line in process.stdout:
                # Check if the line is a notice and format it as needed
                if "[notice]" in line:
                    formatted_line = f"[*] {line.split('[notice]')[1].strip()}"
                    dpg.set_value("Tor logs", f"{dpg.get_value('Tor logs')}{formatted_line}\n")
                    if "[notice] Bootstrapped 100% (done): Done" in line:
                        dpg.set_value("Popup text", "Proxies are running")
                        dpg.show_item("Popup window")
            for line in process.stderr:
                # If you want to handle stderr similarly, you can do so
                if "[notice]" in line:
                    formatted_line = f"[*] {line.split('[notice]')[1].strip()}"
                    dpg.set_value("Tor logs", f"{dpg.get_value('Tor logs')}{formatted_line}\n")
        except Exception as e:
            raise e


    def start():
        try:
            process = execute_command(f"{Tor.executable} -f {Tor.config_file}")
            start_thread(Tor.print_output, process)
        except Exception as e:
            return e

    def stop():
        dpg.set_value("Tor logs", "")
        dpg.set_value("Proxy list", [])
        process = terminate_process("tor.exe")
        if process:
            dpg.set_value("Tor logs", f"{dpg.get_value('Tor logs')}[*] {process}")

    def configure(options):
        try:
            with open(Tor.config_file, "w") as file:
                for option in options:
                    file.write(option + "\n")
        except Exception as e:
            raise e


class VPN:
    url = "https://www.vpnbook.com"
    password_url = "https://www.vpnbook.com/password.php"

    def scrape():
        try:
            servers = VPN.get_servers()
            
            dpg.set_value("VPN list", [])
            dpg.configure_item("VPN list", items=[f"{server['server']} - {server['country']}" for server in servers])

            username = "vpnbook"
            password = VPN.download_password()
            VPN.load_password()
        except Exception as e:
            dpg.set_value("Popup text", e)
            dpg.show_item("Popup window")

    def get_servers():
        try:
            response = requests.get(VPN.url)
            if response.status_code != 200:
                raise response.content

            soup = BeautifulSoup(response.text, "html.parser")
            servers = []

            for link in reversed(soup.find_all("a", href=True)):
                if "Download" in link.text:
                    server_name = link.text.split()[1]
                    country_code = "".join(
                        [char for char in server_name if char.isalpha()]
                    )

                    if country_code.upper() == "UK":
                        country_name = "United Kingdom"
                    else:
                        country = pycountry.countries.get(alpha_2=country_code.upper())
                        country_name = country.name if country else "Unknown"


                    servers.append(
                        {
                            "server": server_name,
                            "country": country_name,
                            "url": VPN.url + link["href"],
                        }
                    )

            return servers
        except Exception as e:
            raise e
        
    def download_password():
        try:
            response = requests.get(VPN.password_url)

            if response.status_code == 200:
                path = os.path.join(get_base_path(), "vpn_password.JPEG")
                with open(path, "wb") as file:
                    file.write(response.content)
            else:
                raise "Failed to download image"
        except Exception as e:
            raise e
        
    def load_password():
        try:
            file = os.path.join(get_base_path(), "vpn_password.JPEG")
            if os.path.exists(file):
                width, height, channels, data = dpg.load_image(file)
                dpg.configure_item("VPN Password texture", width=width, height=height, default_value=data)
                dpg.show_item("VPN Password text")
                dpg.show_item("VPN Password image")
            else:
                dpg.set_value("Popup text", "Password not found")
                dpg.show_item("Popup window")
        except Exception as e:
            dpg.set_value("Popup text", e)
            dpg.show_item("Popup window")


def new_shell():
    global shell_count
    shell_count += 1

    with dpg.window(label=f"Shell {shell_count}", autosize=True):
        with dpg.menu_bar():
            with dpg.menu(label="File"):
                dpg.add_menu_item(
                    label="Save",
                    callback=lambda: save_item_to_file(f"Shell Input {shell_count}"),
                )
                dpg.add_menu_item(
                    label="Open",
                    callback=lambda: open_file_to_item(f"Shell Input {shell_count}"),
                )
                dpg.add_menu_item(label="New", callback=new_shell)
        dpg.add_input_text(
            multiline=True, tag=f"Shell Input {shell_count}", width=450, height=225
        )
        dpg.add_button(
            label="Execute",
            width=450,
            callback=lambda: execute_source(f"Shell Input {shell_count}"),
        )


def main():
    dpg.create_context()

    with dpg.window(label="Shell", autosize=True, tag="Shell window", show=False):
        global shell_count
        shell_count = 0

        with dpg.menu_bar():
            with dpg.menu(label="File"):
                dpg.add_menu_item(
                    label="Save", callback=lambda: save_item_to_file("Shell Input 0")
                )
                dpg.add_menu_item(
                    label="Open", callback=lambda: open_file_to_item("Shell Input 0")
                )
                dpg.add_menu_item(label="New", callback=new_shell)

        dpg.add_input_text(
            multiline=True,
            tag=f"Shell Input 0",
            width=400,
            default_value='print("Hello World")\n',
        )
        dpg.add_button(
            label="Execute",
            width=400,
            callback=lambda: execute_source(f"Shell Input 0"),
        )

    with dpg.window(label="Proxy", autosize=True, tag="Proxy window", show=False):
        global proxy_list
        proxy_list = []
        with dpg.tab_bar():
            with dpg.tab(label="Configure"):
                dpg.add_input_int(
                    label="Count", default_value=1, width=357, tag="Proxy count"
                )
                dpg.add_input_text(
                    readonly=True,
                    multiline=True,
                    default_value="Logs\n",
                    width=400,
                    tag="Tor logs",
                )
                with dpg.group(horizontal=True):
                    dpg.add_button(
                        label="Start",
                        width=198,
                        tag="Start Tor button",
                        callback=Tor.run,
                    )
                    dpg.add_button(
                        label="Stop",
                        width=198,
                        tag="Stop Tor button",
                        indent=202,
                        callback=Tor.stop,
                    )
            with dpg.tab(label="Proxies"):
                dpg.add_listbox(tag="Proxy list", items=proxy_list)

            with dpg.tab(label="Description"):
                with dpg.child_window(width=480, height=270, horizontal_scrollbar=True):
                    dpg.add_text(
                        """Tor is a connection-based low-latency anonymous communication system.

Clients choose a source-routed path through a set of relays, and negotiate
a "virtual circuit" through the network, in which each relay knows its
predecessor and successor, but no others. Traffic flowing down the circuit
is decrypted at each relay, which reveals the downstream relay.

Basically, Tor provides a distributed network of relays. Users bounce
their TCP streams (web traffic, ftp, ssh, etc) around the relays, and
recipients, observers, and even the relays themselves have difficulty
learning which users connected to which destinations.

This package enables only a Tor client by default, but it can also be
configured as a relay and/or a hidden service easily.

Client applications can use the Tor network by connecting to the local
socks proxy interface provided by your Tor instance. If the application
itself does not come with socks support, you can use a socks client such
as torsocks.

Note that Tor does no protocol cleaning on application traffic. There is a
danger that application protocols and associated programs can be induced
to reveal information about the user. Tor depends on Torbutton and similar
protocol cleaners to solve this problem. For best protection when web
surfing, the Tor Project recommends that you use the Tor Browser Bundle, a
standalone tarball that includes static builds of Tor, Torbutton, and a
modified Firefox that is patched to fix a variety of privacy bugs.""")

    with dpg.window(label="VPN (needs update)", autosize=True, tag="VPN window", show=False):
        global vpn_list
        vpn_list = []

        placeholder_width, placeholder_height = 100, 13  # Arbitrary size
        empty_data = [0] * (placeholder_width * placeholder_height * 4)

        with dpg.texture_registry(show=False):
            dpg.add_dynamic_texture(width=placeholder_width, height=placeholder_height, default_value=empty_data, tag="VPN Password texture")

        dpg.add_listbox(items=vpn_list, tag="VPN list")
        with dpg.group(horizontal=True):
            dpg.add_text("Password: ", tag="VPN Password text", show=False)
            with dpg.group():
                dpg.add_spacer(width=8)
                dpg.add_image("VPN Password texture", show=False, tag="VPN Password image")
        dpg.add_button(label="Scrape", width=272, callback=VPN.scrape)
        dpg.add_button(label="Download", width=272)
        dpg.add_button(label="Connect", width=272)

    with dpg.window(label="IP Info", autosize=True, tag="IP Info window", show=False):
        dpg.add_input_text(hint="<IP Address>", width=300, tag="IP address Input")
        dpg.add_button(label="Request", width=300, callback=view_ip_info)
        dpg.add_spacer(width=2)
        dpg.add_input_text(
            multiline=True, readonly=True, width=300, tag="IP address output"
        )

    with dpg.window(tag="Popup window", show=False, modal=True, autosize=True):
        dpg.add_text(tag="Popup text")

    with dpg.viewport_menu_bar():
        with dpg.menu(label="Applications"):
            dpg.add_menu_item(
                label="Shell", callback=lambda: dpg.show_item("Shell window")
            )
            dpg.add_menu_item(
                label="Proxy", callback=lambda: dpg.show_item("Proxy window")
            )
            dpg.add_menu_item(label="VPN", callback=lambda: dpg.show_item("VPN window"))
            dpg.add_menu_item(
                label="IP Info", callback=lambda: dpg.show_item("IP Info window")
            )

    with dpg.font_registry():
        default_font = dpg.add_font("FiraCode-Medium.ttf", 17)
    dpg.bind_font(default_font)

    with dpg.theme() as theme:
        with dpg.theme_component(dpg.mvAll):
            dpg.add_theme_style(dpg.mvStyleVar_ScrollbarRounding, 2)
            dpg.add_theme_style(dpg.mvStyleVar_WindowRounding, 3)
            dpg.add_theme_style(dpg.mvStyleVar_ChildRounding, 2)
            dpg.add_theme_style(dpg.mvStyleVar_PopupRounding, 2)
            dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 2)
            dpg.add_theme_style(dpg.mvStyleVar_GrabRounding, 2)
            dpg.add_theme_style(dpg.mvStyleVar_TabRounding, 2)

            dpg.add_theme_color(dpg.mvThemeCol_Text, (255, 255, 255, 255))
            dpg.add_theme_color(dpg.mvThemeCol_TabActive, (40, 40, 40, 255))
            dpg.add_theme_color(dpg.mvThemeCol_SliderGrabActive, (70, 70, 70, 255))
            dpg.add_theme_color(dpg.mvThemeCol_TextDisabled, (100, 100, 100, 255))
            dpg.add_theme_color(dpg.mvThemeCol_TabUnfocused, (30, 30, 30, 255))
            dpg.add_theme_color(dpg.mvThemeCol_Button, (40, 40, 40, 255))
            dpg.add_theme_color(dpg.mvThemeCol_WindowBg, (20, 20, 20, 255))
            dpg.add_theme_color(dpg.mvThemeCol_TabUnfocusedActive, (50, 50, 50, 255))
            dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (60, 60, 60, 255))
            dpg.add_theme_color(dpg.mvThemeCol_ChildBg, (30, 30, 30, 255))
            dpg.add_theme_color(dpg.mvThemeCol_DockingPreview, (40, 40, 40, 255))
            dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (70, 70, 70, 255))
            dpg.add_theme_color(dpg.mvThemeCol_Border, (80, 80, 80, 255))
            dpg.add_theme_color(dpg.mvThemeCol_DockingEmptyBg, (10, 10, 10, 255))
            dpg.add_theme_color(dpg.mvThemeCol_Header, (40, 40, 40, 255))
            dpg.add_theme_color(dpg.mvThemeCol_PopupBg, (40, 40, 40, 255))
            dpg.add_theme_color(dpg.mvThemeCol_PlotLines, (100, 100, 100, 255))
            dpg.add_theme_color(dpg.mvThemeCol_HeaderHovered, (70, 70, 70, 255))
            dpg.add_theme_color(dpg.mvThemeCol_BorderShadow, (40, 40, 40, 255))
            dpg.add_theme_color(dpg.mvThemeCol_PlotLinesHovered, (110, 110, 110, 255))
            dpg.add_theme_color(dpg.mvThemeCol_HeaderActive, (60, 60, 60, 255))
            dpg.add_theme_color(dpg.mvThemeCol_FrameBg, (50, 50, 50, 255))
            dpg.add_theme_color(dpg.mvThemeCol_PlotHistogram, (100, 100, 100, 255))
            dpg.add_theme_color(dpg.mvThemeCol_Separator, (60, 60, 60, 255))
            dpg.add_theme_color(dpg.mvThemeCol_FrameBgHovered, (50, 50, 50, 255))
            dpg.add_theme_color(
                dpg.mvThemeCol_PlotHistogramHovered, (110, 110, 110, 255)
            )
            dpg.add_theme_color(dpg.mvThemeCol_SeparatorHovered, (80, 80, 80, 255))
            dpg.add_theme_color(dpg.mvThemeCol_FrameBgActive, (60, 60, 60, 255))
            dpg.add_theme_color(dpg.mvThemeCol_TableHeaderBg, (40, 40, 40, 255))
            dpg.add_theme_color(dpg.mvThemeCol_SeparatorActive, (50, 50, 50, 255))
            dpg.add_theme_color(dpg.mvThemeCol_TitleBg, (30, 30, 30, 255))
            dpg.add_theme_color(dpg.mvThemeCol_TableBorderStrong, (60, 60, 60, 255))
            dpg.add_theme_color(dpg.mvThemeCol_ResizeGrip, (40, 40, 40, 255))
            dpg.add_theme_color(dpg.mvThemeCol_TitleBgActive, (50, 50, 50, 255))
            dpg.add_theme_color(dpg.mvThemeCol_TableBorderLight, (80, 80, 80, 255))
            dpg.add_theme_color(dpg.mvThemeCol_ResizeGripHovered, (60, 60, 60, 255))
            dpg.add_theme_color(dpg.mvThemeCol_TitleBgCollapsed, (20, 20, 20, 255))
            dpg.add_theme_color(dpg.mvThemeCol_TableRowBg, (30, 30, 30, 255))
            dpg.add_theme_color(dpg.mvThemeCol_ResizeGripActive, (70, 70, 70, 255))
            dpg.add_theme_color(dpg.mvThemeCol_MenuBarBg, (10, 10, 10, 255))
            dpg.add_theme_color(dpg.mvThemeCol_TableRowBgAlt, (40, 40, 40, 255))
            dpg.add_theme_color(dpg.mvThemeCol_Tab, (20, 20, 20, 255))
            dpg.add_theme_color(dpg.mvThemeCol_ScrollbarBg, (10, 10, 10, 255))
            dpg.add_theme_color(dpg.mvThemeCol_TextSelectedBg, (70, 70, 70, 255))
            dpg.add_theme_color(dpg.mvThemeCol_TabHovered, (50, 50, 50, 255))
            dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrab, (40, 40, 40, 255))
            dpg.add_theme_color(dpg.mvThemeCol_DragDropTarget, (40, 40, 40, 255))
            dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrabHovered, (60, 60, 60, 255))
            dpg.add_theme_color(dpg.mvThemeCol_NavHighlight, (80, 80, 80, 255))
            dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrabActive, (80, 80, 80, 255))
            dpg.add_theme_color(
                dpg.mvThemeCol_NavWindowingHighlight, (100, 100, 100, 255)
            )
            dpg.add_theme_color(dpg.mvThemeCol_CheckMark, (150, 150, 150, 255))
            dpg.add_theme_color(dpg.mvThemeCol_NavWindowingDimBg, (30, 30, 30, 255))
            dpg.add_theme_color(dpg.mvThemeCol_SliderGrab, (70, 70, 70, 255))
            dpg.add_theme_color(dpg.mvThemeCol_ModalWindowDimBg, (10, 10, 10, 255))

    dpg.bind_theme(theme)

    dpg.create_viewport(
        title=f"{title} by {author}",
        width=1010,
        height=568,
        clear_color=(15, 15, 15, 255),
    )
    dpg.setup_dearpygui()
    dpg.show_viewport()
    dpg.start_dearpygui()
    dpg.destroy_context()


if __name__ == "__main__":
    title = "CyberUI"
    author = "@batubyte"
    update_date = "2/8/2025"

    if platform.system() == "Windows":
        main()
    else:
        print("Linux soon.")
