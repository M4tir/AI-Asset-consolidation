import sys
import re
import os
import socket
import configparser
from pathlib import Path
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTextEdit, QFileDialog, QScrollArea,
    QProgressBar, QSplitter, QDialog, QMenuBar, QMenu,
    QAction, QMessageBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QDragEnterEvent, QDropEvent, QIcon, QPixmap
import resources_rc  # 确保资源文件存在

# ====================== 配置文件处理 ======================
CONFIG_DIR = Path.home() / '.config' / 'SmartClassifier'
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_FILE = CONFIG_DIR / 'config.ini'

def load_config():
    config = configparser.ConfigParser()
    if CONFIG_FILE.exists():
        config.read(CONFIG_FILE)
    if not config.has_section('Settings'):
        config.add_section('Settings')
    if not config.has_option('Settings', 'theme'):
        config.set('Settings', 'theme', 'Light')
    if not config.has_option('Settings', 'first_run'):
        config.set('Settings', 'first_run', 'true')
    with open(CONFIG_FILE, 'w') as f:
        config.write(f)
    return config

# ====================== 增强正则表达式模块 ======================
class EnhancedPatterns:
    @staticmethod
    def ip_pattern():
        return re.compile(
            r'\b((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}'
            r'(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
            r'(?::\d+)?'
            r'(?:/\d{1,2})?\b'
        )

    @staticmethod
    def domain_pattern():
        return re.compile(
            r'^(?:https?://)?'
            r'((?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z0-9-]{2,63})'
            r'(?::\d+)?'
            r'(?:/|$)',
            re.IGNORECASE
        )

    @staticmethod
    def url_pattern():
        return re.compile(
            r'(https?://[^\s/$.?#]+\.[^\s]*)',
            re.IGNORECASE
        )

    @staticmethod
    def extract_ip_from_url():
        return re.compile(
            r'(?:https?://)?'
            r'((?:\d{1,3}\.){3}\d{1,3})'
            r'(?::\d+)?'
            r'(?:/|$)',
            re.IGNORECASE
        )

# ====================== 智能数据处理核心 ======================
class EnhancedAddressProcessor:
    @staticmethod
    def process_data(raw_data, progress_callback=None):
        results = {
            'ips': set(),
            'ip_segments': set(),
            'internal_ips': set(),
            'domains': set(),
            'urls': set(),
            'texts': set(),
            'invalid_ips': set()
        }

        total = len(raw_data)
        for i, item in enumerate(raw_data):
            item = item.strip()
            if not item:
                continue

            if progress_callback and i % 100 == 0:
                progress_callback(int((i / total) * 100))

            # URL处理
            url_matches = EnhancedPatterns.url_pattern().findall(item)
            for url in url_matches:
                ip_match = EnhancedPatterns.extract_ip_from_url().search(url)
                if ip_match:
                    ip = ip_match.group(1)
                    if EnhancedAddressProcessor.validate_ip_or_cidr(ip):
                        if '/' in ip:
                            results['ip_segments'].add(ip)
                        else:
                            if EnhancedAddressProcessor.is_private_ip(ip):
                                results['internal_ips'].add(ip)
                            else:
                                results['ips'].add(ip)
                    item = item.replace(ip, ' ')

                domain_match = EnhancedPatterns.domain_pattern().search(url)
                if domain_match:
                    domain = domain_match.group(1).lower().rstrip('.')
                    if EnhancedAddressProcessor.is_valid_domain(domain):
                        results['domains'].add(domain)
                    item = item.replace(domain, ' ')

                clean_url = re.sub(r'[<>"\'()]', '', url.split('?')[0]).rstrip('/')
                results['urls'].add(clean_url)
                item = item.replace(url, ' ')

            # IP/CIDR处理
            ip_matches = EnhancedPatterns.ip_pattern().finditer(item)
            for match in ip_matches:
                full_match = match.group(0)
                base_ip = full_match.split(':')[0].split('/')[0]

                if '/' in full_match:
                    if EnhancedAddressProcessor.validate_cidr(full_match):
                        results['ip_segments'].add(full_match)
                elif EnhancedAddressProcessor.is_valid_ip(base_ip):
                    if EnhancedAddressProcessor.is_private_ip(base_ip):
                        results['internal_ips'].add(base_ip)
                    else:
                        results['ips'].add(base_ip)
                else:
                    results['invalid_ips'].add(full_match)
                item = item.replace(full_match, ' ')

            # 域名验证
            domain_match = EnhancedPatterns.domain_pattern().search(item)
            if domain_match:
                domain = domain_match.group(1).lower().rstrip('.')
                if EnhancedAddressProcessor.is_valid_domain(domain):
                    results['domains'].add(domain)
                item = item.replace(domain, ' ')

            # 中文处理
            if re.search(r'[\u4e00-\u9fa5]', item):
                clean_text = re.sub(r'\s+', ' ', item).strip()
                if clean_text:
                    results['texts'].add(clean_text)
                item = ''

            # 无效数据
            if item.strip():
                results['invalid_ips'].add(item)

        return {
            'ips': sorted(results['ips'], key=lambda x: tuple(map(int, x.split('.')))),
            'ip_segments': sorted(
                results['ip_segments'],
                key=lambda x: (
                    tuple(map(int, x.split('/')[0].split('.'))),
                    int(x.split('/')[1])
                )
            ),
            'internal_ips': sorted(
                results['internal_ips'],
                key=lambda x: tuple(map(int, x.split('.')))
            ),
            'domains': sorted(results['domains']),
            'urls': sorted(results['urls']),
            'texts': sorted(results['texts']),
            'invalid_ips': sorted(results['invalid_ips'])
        }

    @staticmethod
    def validate_ip_or_cidr(address):
        if '/' in address:
            return EnhancedAddressProcessor.validate_cidr(address)
        return EnhancedAddressProcessor.is_valid_ip(address)

    @staticmethod
    def is_valid_ip(ip):
        try:
            socket.inet_aton(ip)
            octets = ip.split('.')
            return all(0 <= int(o) <= 255 for o in octets)
        except (socket.error, ValueError):
            return False

    @staticmethod
    def validate_cidr(cidr):
        try:
            ip, mask = cidr.split('/')
            mask = int(mask)
            if not (0 <= mask <= 32):
                return False
            socket.inet_aton(ip)
            return True
        except (ValueError, socket.error):
            return False

    @staticmethod
    def is_private_ip(ip):
        octets = list(map(int, ip.split('.')))
        if octets[0] == 10:
            return True
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True
        if octets[0] == 192 and octets[1] == 168:
            return True
        return False

    @staticmethod
    def is_valid_domain(domain):
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        tld = parts[-1]
        return len(tld) >= 2 and not tld.isdigit()

# ====================== 处理线程 ======================
class EnhancedProcessThread(QThread):
    progress_updated = pyqtSignal(int)
    result_ready = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, input_path, output_dir):
        super().__init__()
        self.input_path = input_path
        self.output_dir = output_dir
        self._is_running = True

    def run(self):
        try:
            raw_data = []
            with open(self.input_path, 'r', encoding='utf-8', errors='replace') as f:
                while self._is_running:
                    line = f.readline()
                    if not line:
                        break
                    raw_data.append(line.strip())

            results = EnhancedAddressProcessor.process_data(
                raw_data,
                progress_callback=lambda v: self.progress_updated.emit(v)
            )

            os.makedirs(self.output_dir, exist_ok=True)
            for category, items in results.items():
                if items:
                    try:
                        with open(os.path.join(self.output_dir, f"{category}.txt"), 'w', encoding='utf-8') as f:
                            f.write('\n'.join(items))
                    except IOError as e:
                        self.error_occurred.emit(f"保存{category}失败: {str(e)}")

            self.result_ready.emit({k: len(v) for k, v in results.items()})

        except Exception as e:
            self.error_occurred.emit(f"处理失败: {str(e)}")
        finally:
            self.progress_updated.emit(100)

    def stop(self):
        self._is_running = False

# ====================== GUI界面组件 ======================
class FirstRunDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("欢迎使用")
        self.setWindowIcon(QIcon(":/icon.ico"))
        self.setFixedSize(300, 350)

        layout = QVBoxLayout()
        self.lbl_qrcode = QLabel()
        pixmap = QPixmap(":/qrcode.png").scaled(200, 200, Qt.KeepAspectRatio)
        self.lbl_qrcode.setPixmap(pixmap)
        self.lbl_qrcode.setAlignment(Qt.AlignCenter)

        self.lbl_text = QLabel("扫描二维码关注开发者\n（6秒后自动关闭）")
        self.lbl_text.setAlignment(Qt.AlignCenter)

        self.btn_close = QPushButton("立即关闭")
        self.btn_close.clicked.connect(self.close)

        layout.addWidget(self.lbl_qrcode)
        layout.addWidget(self.lbl_text)
        layout.addWidget(self.btn_close)
        self.setLayout(layout)

        QTimer.singleShot(1000000, self.close)

class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("关于")
        self.setWindowIcon(QIcon(":/icon.ico"))
        self.setFixedSize(500, 400)

        layout = QVBoxLayout()
        self.lbl_image = QLabel()
        pixmap = QPixmap(":/about.png")
        self.lbl_image.setPixmap(pixmap)
        self.lbl_image.setAlignment(Qt.AlignCenter)

        self.lbl_text = QLabel("星悦智能数据分类工具 v7.0\n\n"
                               "开发团队: 星悦安全\n"
                               "发布日期: 2024-01-01\n"
                               "联系方式: www.xingyue404.icu")
        self.lbl_text.setAlignment(Qt.AlignCenter)

        layout.addWidget(self.lbl_image)
        layout.addWidget(self.lbl_text)
        self.setLayout(layout)

class EnhancedMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.config = load_config()
        self.display_containers = {}  # 新增显示容器字典
        self.init_window()
        self.init_data()
        self.init_menu()
        self.init_ui()
        self.setAcceptDrops(True)

        if self.config.getboolean('Settings', 'first_run'):
            dialog = FirstRunDialog(self)
            dialog.exec_()
            self.config.set('Settings', 'first_run', 'false')
            with open(CONFIG_FILE, 'w') as f:
                self.config.write(f)

    def choose_input(self):
        """选择输入文件"""
        path, _ = QFileDialog.getOpenFileName(
            self, "选择输入文件", "", "文本文件 (*.txt)")
        if path:
            self.input_path = path
            self.input_label.setText(os.path.basename(path))

    def choose_output(self):
        """选择输出目录"""
        path = QFileDialog.getExistingDirectory(
            self, "选择输出目录", os.path.expanduser("~/Desktop"))
        if path:
            self.output_dir = path
            self.output_label.setText(path)

    def start_processing(self):
        """开始处理"""
        if not self.input_path:
            self.show_message("❌ 请先选择输入文件")
            return

        if not os.path.exists(self.input_path):
            self.show_message("❌ 输入文件不存在")
            return

        self.btn_process.setEnabled(False)
        self.btn_input.setEnabled(False)
        self.btn_output.setEnabled(False)
        self.progress_bar.setValue(0)
        self.result_display.clear()

        # 初始化所有显示区域
        for category in self.display_actions:
            getattr(self, f"{category}_display").clear()

        self.worker = EnhancedProcessThread(self.input_path, self.output_dir)
        self.worker.progress_updated.connect(self.progress_bar.setValue)
        self.worker.result_ready.connect(self.on_process_finished)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.start()

    def on_process_finished(self, results):
        """处理完成回调"""
        self.btn_process.setEnabled(True)
        self.btn_input.setEnabled(True)
        self.btn_output.setEnabled(True)
        self.progress_bar.setValue(100)

        # 显示统计结果
        result_text = "\n".join([f"{k}: {v}条" for k, v in results.items()])
        self.show_message(f"✅ 处理完成\n{result_text}")

        # 加载结果文件到对应显示区域
        self.load_result_files()

    def init_window(self):
        self.setWindowTitle("星悦智能数据分类工具 v7.0")
        self.setWindowIcon(QIcon(":/icon.ico"))
        self.setGeometry(100, 100, 1400, 900)

    def init_data(self):
        self.output_dir = os.path.expanduser("~/Desktop/分类结果")
        self.input_path = None
        self.theme = self.config.get('Settings', 'theme')

    def init_menu(self):
        menubar = self.menuBar()

        # 显示菜单
        display_menu = menubar.addMenu("显示")
        self.display_actions = {
            'ips': QAction("公网 IP", self, checkable=True, checked=True),
            'ip_segments': QAction("IP 网段", self, checkable=True, checked=True),
            'domains': QAction("域名", self, checkable=True, checked=True),
            'urls': QAction("URL", self, checkable=True, checked=True),
            'texts': QAction("文本内容", self, checkable=True, checked=True)
        }
        for action in self.display_actions.values():
            action.triggered.connect(self.update_display)
            display_menu.addAction(action)

        # 主题菜单
        theme_menu = menubar.addMenu("主题")
        light_action = QAction("Light", self)
        light_action.triggered.connect(lambda: self.change_theme("Light"))
        dark_action = QAction("Dark", self)
        dark_action.triggered.connect(lambda: self.change_theme("Dark"))
        theme_menu.addAction(light_action)
        theme_menu.addAction(dark_action)

        # 帮助菜单
        help_menu = menubar.addMenu("帮助")
        about_action = QAction("关于", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def show_about(self):
        dialog = AboutDialog(self)
        dialog.exec_()

    def init_ui(self):
        self.create_widgets()
        self.setup_layout()
        self.connect_signals()
        self.set_theme(self.theme)
        self.load_display_settings()
        self.disable_drag_on_children()

    def create_widgets(self):
        self.input_label = QLabel("未选择文件")
        self.output_label = QLabel(self.output_dir)
        self.btn_input = QPushButton("📁 选择输入文件")
        self.btn_output = QPushButton("📂 选择输出目录")
        self.btn_process = QPushButton("▶ 开始处理")
        self.btn_process.setFixedSize(420, 60)
        self.btn_process.setStyleSheet("""
            QPushButton {
                font-size: 20px; background-color: #388E3C;
                color: white; border: none; border-radius: 5px;
            }
            QPushButton:hover { background-color: #005ea6; }
        """)
        self.progress_bar = QProgressBar()
        self.progress_bar.setFormat("%p%")
        self.result_display = QTextEdit()
        self.ips_display = QTextEdit()
        self.ip_segments_display = QTextEdit()
        self.domains_display = QTextEdit()
        self.urls_display = QTextEdit()
        self.texts_display = QTextEdit()

    def setup_layout(self):
        main_layout = QVBoxLayout()
        main_layout.addLayout(self.create_top_layout())

        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.create_middle_widget())
        splitter.addWidget(self.create_bottom_widget())
        splitter.setSizes([600, 300])

        main_layout.addWidget(splitter)
        container = QWidget()
        container.setLayout(main_layout)

        scroll = QScrollArea()
        scroll.setWidget(container)
        scroll.setWidgetResizable(True)
        self.setCentralWidget(scroll)

    def create_top_layout(self):
        layout = QHBoxLayout()
        file_layout = QVBoxLayout()
        file_layout.addWidget(QLabel("输入文件:"))
        file_layout.addWidget(self.input_label)
        file_layout.addWidget(self.btn_input)

        output_layout = QVBoxLayout()
        output_layout.addWidget(QLabel("输出目录:"))
        output_layout.addWidget(self.output_label)
        output_layout.addWidget(self.btn_output)

        start_layout = QVBoxLayout()
        start_layout.addWidget(QLabel(""))
        start_layout.addWidget(self.btn_process)
        start_layout.addWidget(QLabel(""))

        layout.addLayout(file_layout)
        layout.addLayout(output_layout)
        layout.addLayout(start_layout)
        return layout

    def create_middle_widget(self):
        widget = QWidget()
        splitter = QSplitter()

        def add_category(category, label):
            container = QWidget()
            layout = QVBoxLayout()
            layout.addWidget(QLabel(label))
            layout.addWidget(getattr(self, f"{category}_display"))
            container.setLayout(layout)
            self.display_containers[category] = container
            splitter.addWidget(container)

        add_category('ips', '公网 IP')
        add_category('ip_segments', 'IP 网段')
        add_category('domains', '域名')
        add_category('urls', 'URL')
        add_category('texts', '文本内容')

        layout = QHBoxLayout()
        layout.addWidget(splitter)
        widget.setLayout(layout)
        return widget

    def create_bottom_widget(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("处理结果:"))
        layout.addWidget(self.result_display)
        layout.addWidget(self.progress_bar)
        widget.setLayout(layout)
        return widget

    def connect_signals(self):
        self.btn_input.clicked.connect(self.choose_input)
        self.btn_output.clicked.connect(self.choose_output)
        self.btn_process.clicked.connect(self.start_processing)

    def update_display(self):
        splitter = self.findChild(QSplitter)
        visible_containers = []

        for category, action in self.display_actions.items():
            container = self.display_containers.get(category)
            if container:
                visible = action.isChecked()
                container.setVisible(visible)
                if visible:
                    visible_containers.append(container)
                self.config.set('Display', category, str(visible))

        if visible_containers:
            new_width = splitter.width() // len(visible_containers)
            splitter.setSizes([new_width] * len(visible_containers))

        with open(CONFIG_FILE, 'w') as f:
            self.config.write(f)

    def load_display_settings(self):
        if not self.config.has_section('Display'):
            self.config.add_section('Display')
        for category in self.display_actions:
            state = self.config.getboolean('Display', category, fallback=True)
            self.display_actions[category].setChecked(state)
            container = self.display_containers.get(category)
            if container:
                container.setVisible(state)
        self.update_display()

    def load_result_files(self):
        try:
            for category in self.display_actions:
                file_path = os.path.join(self.output_dir, f"{category}.txt")
                widget = getattr(self, f"{category}_display")
                if os.path.exists(file_path):
                    with open(file_path, 'r', encoding='utf-8') as f:
                        widget.setPlainText(f.read())
        except Exception as e:
            self.show_message(f"❌ 加载结果文件失败: {str(e)}")

    def on_error(self, message):
        self.btn_process.setEnabled(True)
        self.btn_input.setEnabled(True)
        self.btn_output.setEnabled(True)
        self.show_message(f"❌ 错误: {message}")
        self.progress_bar.setValue(0)

    def show_message(self, text):
        self.result_display.append(text)

    def closeEvent(self, event):
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
        event.accept()

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        for url in event.mimeData().urls():
            file_path = url.toLocalFile()
            if file_path.endswith('.txt'):
                self.input_path = file_path
                self.input_label.setText(os.path.basename(file_path))
                break

    def set_theme(self, theme):
        self.theme = theme
        self.config.set('Settings', 'theme', theme)
        with open(CONFIG_FILE, 'w') as f:
            self.config.write(f)
        if theme == "Light":
            self.setStyleSheet("""
                QWidget { background-color: #f5f5f5; }
                QTextEdit, QComboBox { background-color: white; }
            """)
        else:
            self.setStyleSheet("""
                QWidget { background-color: #2d2d2d; color: #ffffff; }
                QTextEdit, QComboBox { background-color: #404040; }
            """)

    def change_theme(self, theme):
        self.set_theme(theme)

    def disable_drag_on_children(self):
        """禁用所有子控件的拖放功能"""

        def recursive_disable(widget):
            widget.setAcceptDrops(False)
            for child in widget.children():
                if isinstance(child, QWidget):
                    recursive_disable(child)

        # 排除主窗口的中央组件
        if self.centralWidget():
            for child in self.centralWidget().children():
                if isinstance(child, QWidget) and child != self.centralWidget():
                    recursive_disable(child)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = EnhancedMainWindow()
    window.show()
    sys.exit(app.exec_())