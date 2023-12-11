#!/usr/bin/python3
import proxmoxer
import PySimpleGUI as sg
gui = 'TK'
import requests
from datetime import datetime
from configparser import ConfigParser
import random
import sys
import copy
import os
import subprocess
from time import sleep
from io import StringIO

class G:
	hostpool = []
	spiceproxy_conv = {}
	proxmox = None
	vvcmd = None
	scaling = 1
	title = ''
	backend = 'pve'
	user = ""
	token_name = None
	token_value = None
	totp = False
	imagefile = None
	kiosk = False
	fullscreen = True
	verify_ssl = True
	icon = None
	inidebug = False
	addl_params = None
	theme = 'DarkBlue'
	guest_type = 'both'

def loadconfig(config_location = None):
	if config_location:
		config = ConfigParser(delimiters='=')
		try:
			config.read(config_location,encoding='utf-8')
		except Exception as e:
			win_popup_button(f'无法读取配置文件，请检查配置文件:\n{e!r}', '确定')
			config_location = None
	if not config_location:
		if os.name == 'nt':
			config_location = os.path.join(os.getcwd(), 'vdiclient.ini') 
			if not os.path.exists(config_location):
				config_location = f'{os.getenv("PROGRAMFILES")}\\VDIClient\\vdiclient.ini'
			if not os.path.exists(config_location):
				config_location = f'{os.getenv("PROGRAMFILES(x86)")}\\VDIClient\\vdiclient.ini'
			if not os.path.exists(config_location):
				config_location = 'C:\\Program Files\\VDIClient\\vdiclient.ini'
			if not os.path.exists(config_location):
				win_popup_button(f'无法读取配置文件，请检查配置文件!', '确定')
				return False
		elif os.name == 'posix':
			config_location = os.path.expanduser('~/.config/VDIClient/vdiclient.ini')
			if not os.path.exists(config_location):
				config_location = '/etc/vdiclient/vdiclient.ini'
			if not os.path.exists(config_location):
				config_location = '/usr/local/etc/vdiclient/vdiclient.ini'
			if not os.path.exists(config_location):
				win_popup_button(f'无法读取配置文件，请检查配置文件!', '确定')
				return False
		config = ConfigParser(delimiters='=')
		try:
			config.read(config_location,encoding='utf-8')
		except Exception as e:
			win_popup_button(f'无法读取配置文件，请检查配置文件:\n{e!r}', '确定')
			config_location = None
	if not 'General' in config:
		win_popup_button(f'无法读取配置文件，请检查配置文件:\n请检查 `General` 中的相关配置!', '确定')
		return False
	else:
		if 'title' in config['General']:
			G.title = config['General']['title']
		if 'theme' in config['General']:
			G.theme = config['General']['theme']
		if 'icon' in config['General']:
			if os.path.exists(config['General']['icon']):
				G.icon = config['General']['icon']
		if 'logo' in config['General']:
			if os.path.exists(config['General']['logo']):
				G.imagefile = config['General']['logo']
		if 'kiosk' in config['General']:
			G.kiosk = config['General'].getboolean('kiosk')
		if 'fullscreen' in config['General']:
			G.fullscreen = config['General'].getboolean('fullscreen')
		if 'inidebug' in config['General']:
			G.inidebug = config['General'].getboolean('inidebug')
		if 'guest_type' in config['General']:
			G.guest_type = config['General']['guest_type']
	if not 'Authentication' in config:
		win_popup_button(f'无法读取配置文件，请检查配置文件:\n未定义 `Authentication` 验证部份!', '确定')
		return False
	else:
		if 'auth_backend' in config['Authentication']:
			G.backend = config['Authentication']['auth_backend']
		if 'auth_totp' in config['Authentication']:
			G.totp = config['Authentication'].getboolean('auth_totp')
		if 'tls_verify' in config['Authentication']:
			G.verify_ssl = config['Authentication'].getboolean('tls_verify')
		if 'user' in config['Authentication']:
				G.user = config['Authentication']['user']
		if 'token_name' in config['Authentication']:
				G.token_name = config['Authentication']['token_name']
		if 'token_value' in config['Authentication']:
				G.token_value = config['Authentication']['token_value']
	if not 'Hosts' in config:
		win_popup_button(f'无法读取配置文件，请检查配置文件:\n未定义主机名称，请检查HOSTS部份!', '确定')
		return False
	else:
		for key in config['Hosts']:
			G.hostpool.append({
				'host': key,
				'port': int(config['Hosts'][key])
			})
	if 'SpiceProxyRedirect' in config:
		for key in config['SpiceProxyRedirect']:
			G.spiceproxy_conv[key] = config['SpiceProxyRedirect'][key]
	if 'AdditionalParameters' in config:
		G.addl_params = {}
		for key in config['AdditionalParameters']:
			G.addl_params[key] = config['AdditionalParameters'][key]
	return True

def win_popup(message):
	layout = [
		[sg.Text(message)]
	]
	window = sg.Window('Message', layout, return_keyboard_events=True, no_titlebar=True, keep_on_top=True, finalize=True)
	window.bring_to_front()
	_, _ = window.read(timeout=10)
	return window
	
def win_popup_button(message, button):
	layout = [
				[sg.Text(message)],
				[sg.Button(button)]
			]
	window = sg.Window('Message', layout, return_keyboard_events=True, no_titlebar=True, keep_on_top=True, finalize=True)
	window.Element(button).SetFocus()
	while True:
		event, values = window.read()
		if event in (button, sg.WIN_CLOSED, '确定', '\r', 'special 16777220', 'special 16777221'):
			window.close()
			return

def setmainlayout():
	layout = []
	if G.imagefile:
		layout.append([sg.Image(G.imagefile), sg.Text(G.title, size =(18*G.scaling, 1*G.scaling), justification='c', font=["Helvetica", 18])])
	else:
		layout.append([sg.Text(G.title, size =(30*G.scaling, 1*G.scaling), justification='c', font=["Helvetica", 18])])
	layout.append([sg.Text("用户帐户", size =(12*G.scaling, 1*G.scaling), font=["Helvetica", 12]), sg.InputText(default_text=G.user,key='-username-', font=["Helvetica", 12])])
	layout.append([sg.Text("用户密码", size =(12*G.scaling, 1*G.scaling),font=["Helvetica", 12]), sg.InputText(key='-password-', password_char='*', font=["Helvetica", 12])])
	
	if G.totp:
		layout.append([sg.Text("OTP Key", size =(12*G.scaling, 1), font=["Helvetica", 12]), sg.InputText(key='-totp-', font=["Helvetica", 12])])
	if G.kiosk:
		layout.append([sg.Button("确定", font=["Helvetica", 14], bind_return_key=True)])
	else:
		layout.append([sg.Button("确定", font=["Helvetica", 14], bind_return_key=True), sg.Button("退出", font=["Helvetica", 14])])
	return layout

def getvms(listonly = False):
	vms = []
	try:
		nodes = []
		for node in G.proxmox.cluster.resources.get(type='node'):
			if node['status'] == 'online':
				nodes.append(node['node'])

		for vm in G.proxmox.cluster.resources.get(type='vm'):
			if vm['node'] not in nodes:
				continue
			if 'template' in vm and vm['template']:
				continue
			if G.guest_type == 'both' or G.guest_type == vm['type']:
				if listonly:
					vms.append(
						{
							'vmid': vm['vmid'],
							'name': vm['name'],
							'node': vm['node']
						}
					)
				else:
					vms.append(vm)
		return vms
	except proxmoxer.core.ResourceException as e:
		win_popup_button(f"无法显示虚拟机列表，请联系管理员！:\n {e!r}", '确定')
		return False

def setvmlayout(vms):
	layout = []
	if G.imagefile:
		layout.append([sg.Image(G.imagefile), sg.Text(G.title, size =(18*G.scaling, 1*G.scaling), justification='c', font=["Helvetica", 18])])
	else:
		layout.append([sg.Text(G.title, size =(30*G.scaling, 1*G.scaling), justification='c', font=["Helvetica", 18])])
	layout.append([sg.Text('请选择您要进入的云桌面：', size =(40*G.scaling, 1*G.scaling), justification='c', font=["Helvetica", 10])])
	layoutcolumn = []
	for vm in vms:
		if not vm["status"] == "unknown":
			connkeyname = f'-CONN|{vm["vmid"]}-'
			layoutcolumn.append([sg.Text(vm['name'], font=["Helvetica", 14], size=(22*G.scaling, 1*G.scaling)), sg.Button('进入', font=["Helvetica", 14], key=connkeyname)])
			layoutcolumn.append([sg.HorizontalSeparator()])
	if len(vms) > 5:
		layout.append([sg.Column(layoutcolumn, scrollable = True, size = [450*G.scaling, None] )])
	else:
		for row in layoutcolumn:
			layout.append(row)
	layout.append([sg.Button('注销', font=["Helvetica", 14])])
	return layout

def iniwin(inistring):
	inilayout = [
			[sg.Multiline(default_text=inistring, size=(800*G.scaling, 600*G.scaling))]
	]
	iniwindow = sg.Window('INI debug', inilayout)
	while True:
		event, values = iniwindow.read()
		if event == None:
			break
	iniwindow.close()
	return True

def vmaction(vmnode, vmid, vmtype):
	status = False
	if vmtype == 'qemu':
		vmstatus = G.proxmox.nodes(vmnode).qemu(str(vmid)).status.get('current')
	else:
		vmstatus = G.proxmox.nodes(vmnode).lxc(str(vmid)).status.get('current')
	if vmstatus['status'] != 'running':
		startpop = win_popup(f'Starting {vmstatus["name"]}...')
		try:
			if vmtype == 'qemu':
				jobid = G.proxmox.nodes(vmnode).qemu(str(vmid)).status.start.post(timeout=28)
			else:
				jobid = G.proxmox.nodes(vmnode).lxc(str(vmid)).status.start.post(timeout=28)
		except proxmoxer.core.ResourceException as e:
			startpop.close()
			win_popup_button(f"无法启动虚拟机，请联系管理员，错误信息:\n {e!r}", '确定')
			return False
		running = False
		i = 0
		while running == False and i < 30:
			try:
				jobstatus = G.proxmox.nodes(vmnode).tasks(jobid).status.get()
			except Exception:
				jobstatus = {}
			if 'exitstatus' in jobstatus:
				startpop.close()
				startpop = None
				if jobstatus['exitstatus'] != 'OK':
					win_popup_button('无法启动虚拟机，请联系管理员处理！', '确定')
					running = True
				else:
					running = True
					status = True
			sleep(1)
			i += 1
		if not status:
			if startpop:
				startpop.close()
			return status
	try:
		if vmtype == 'qemu':
			spiceconfig = G.proxmox.nodes(vmnode).qemu(str(vmid)).spiceproxy.post()
		else: 
			spiceconfig = G.proxmox.nodes(vmnode).lxc(str(vmid)).spiceproxy.post()
	except proxmoxer.core.ResourceException as e:
		win_popup_button(f"无法连接到虚拟机 {vmid}:\n{e!r}\n请联系管理员！", '确定')
		return False
	confignode = ConfigParser()
	confignode['virt-viewer'] = {}
	for key, value in spiceconfig.items():
		if key == 'proxy':
			val = value[7:].lower()
			if val in G.spiceproxy_conv:
				confignode['virt-viewer'][key] = f'http://{G.spiceproxy_conv[val]}'
			else:
				confignode['virt-viewer'][key] = f'{value}'
		else:
			confignode['virt-viewer'][key] = f'{value}'
	if G.addl_params:
		for key, value in G.addl_params.items():
			confignode['virt-viewer'][key] = f'{value}'
	inifile = StringIO('')
	confignode.write(inifile)
	inifile.seek(0)
	inistring = inifile.read()
	if G.inidebug:
		closed = iniwin(inistring)
	connpop = win_popup(f'正在连接到云桌面： {vmstatus["name"]}...')
	pcmd = [G.vvcmd]
	if G.kiosk:
		pcmd.append('--kiosk')
		pcmd.append('--kiosk-quit')
		pcmd.append('on-disconnect')
	elif G.fullscreen:
		pcmd.append('--full-screen')
	pcmd.append('-') 
	process = subprocess.Popen(pcmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
	try:
		output = process.communicate(input=inistring.encode('utf-8'), timeout=5)[0]
	except subprocess.TimeoutExpired:
		pass
	status = True
	connpop.close()
	return status


def setcmd():
	try:
		if os.name == 'nt': 
			import csv
			cmd1 = 'ftype VirtViewer.vvfile'
			result = subprocess.check_output(cmd1, shell=True)
			cmdresult = result.decode('utf-8')
			cmdparts = cmdresult.split('=')
			for row in csv.reader([cmdparts[1]], delimiter = ' ', quotechar = '"'):
				G.vvcmd = row[0]
				break

		elif os.name == 'posix':
			cmd1 = 'which remote-viewer'
			result = subprocess.check_output(cmd1, shell=True)
			G.vvcmd = 'remote-viewer'
	except subprocess.CalledProcessError:
		if os.name == 'nt':
			win_popup_button('没有找到virt-viewer查看器, 请优先安装virt-viewer!', '确定')
		elif os.name == 'posix':
			win_popup_button('没有找到virt-viewer查看器, 请优先安装virt-viewer!', '确定')
		sys.exit()

def pveauth(username, passwd=None, totp=None):
	random.shuffle(G.hostpool)
	err = None
	for hostinfo in G.hostpool:
		host = hostinfo['host']
		if 'port' in hostinfo:
			port = hostinfo['port']
		else:
			port = 8006
		connected = False
		authenticated = False
		if not connected and not authenticated:
			try:
				if G.token_name and G.token_value:
					G.proxmox = proxmoxer.ProxmoxAPI(host, user=f'{username}@{G.backend}',token_name=G.token_name,token_value=G.token_value, verify_ssl=G.verify_ssl, port=port)
				elif totp:
					G.proxmox = proxmoxer.ProxmoxAPI(host, user=f'{username}@{G.backend}', otp=totp, password=passwd, verify_ssl=G.verify_ssl, port=port)
				else:
					G.proxmox = proxmoxer.ProxmoxAPI(host, user=f'{username}@{G.backend}', password=passwd, verify_ssl=G.verify_ssl, port=port)
				connected = True
				authenticated = True
				return connected, authenticated, err
			except proxmoxer.backends.https.AuthenticationError as e:
				err = e
				connected = True
				return connected, authenticated, err
			except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError) as e:
				err = e
				connected = False
	return connected, authenticated, err

def loginwindow():
	layout = setmainlayout()
	if G.user and G.token_name and G.token_value: 
		popwin = win_popup("请稍候, 验证中...")
		connected, authenticated, error = pveauth(G.user)
		popwin.close()
		if not connected:
			win_popup_button(f'不能连接到云桌面服务器，请检查网络连接！\n错误信息: {error}', '确定')
			return False
		elif connected and not authenticated:
			win_popup_button('请输入正确的用户名及密码!忘记密码请联系管理员！', '确定')
			return False
		elif connected and authenticated:
			return True
	else:
		if G.icon:
			window = sg.Window(G.title, layout, return_keyboard_events=True, resizable=False, no_titlebar=G.kiosk, icon=G.icon)
		else:
			window = sg.Window(G.title, layout, return_keyboard_events=True, resizable=False, no_titlebar=G.kiosk)
		while True:
			event, values = window.read()
			if event == '退出' or event == sg.WIN_CLOSED:
				window.close()
				return False
			else:
				if event in ('确定', '\r', 'special 16777220', 'special 16777221'):
					popwin = win_popup("请稍候，正在进行身份验证...")
					user = values['-username-']
					passwd = values['-password-']
					totp = None
					if '-totp-' in values:
						if values['-totp-'] not in (None, ''):
							totp = values['-totp-']
					connected, authenticated, error = pveauth(user, passwd=passwd, totp=totp)
					popwin.close()
					if not connected:
						win_popup_button(f'不能连接到云桌面服务器，请检查网络连接！\n错误信息: {error}', '确定')
					elif connected and not authenticated:
						win_popup_button('请输入正确的用户名及密码!忘记密码请联系管理员！', '确定')
					elif connected and authenticated:
						window.close()
						return True
					
def showvms():
	vms = getvms()
	vmlist = getvms(listonly=True)
	newvmlist = vmlist.copy()
	if vms == False:
		return False
	if len(vms) < 1:
		win_popup_button('没有找到可用的虚拟机，请联系管理员分配可用的虚拟机！', '确定')
		return False
	layout = setvmlayout(vms)

	if G.icon:
		window = sg.Window(G.title, layout, return_keyboard_events=True, finalize=True, resizable=False, no_titlebar=G.kiosk, icon=G.icon)
	else:
		window = sg.Window(G.title, layout, return_keyboard_events=True, finalize=True, resizable=False, no_titlebar=G.kiosk)
	timer = datetime.now()
	while True:
		if (datetime.now() - timer).total_seconds() > 10:
			timer = datetime.now()
			newvmlist = getvms(listonly = True)
			if vmlist != newvmlist:
				vmlist = newvmlist.copy()
				layout = setvmlayout(getvms())
				window.close()
				if G.icon:
					window = sg.Window(G.title, layout, return_keyboard_events=True, finalize=True, resizable=False, no_titlebar=G.kiosk, icon=G.icon)
				else:
					window = sg.Window(G.title, layout, return_keyboard_events=True,finalize=True, resizable=False, no_titlebar=G.kiosk)
				window.bring_to_front()
		event, values = window.read(timeout = 1000)
		if event in ('注销', None):
			window.close()
			return False
		if event.startswith('-CONN'):
			eventparams = event.split('|')
			vmid = eventparams[1][:-1]
			found = False
			for vm in vms:
				if str(vm['vmid']) == vmid:
					found = True
					vmaction(vm['node'], vmid, vm['type'])
			if not found:
				win_popup_button(f'VM {vm["name"]} 当前帐户不可用，请联系管理员处理！', '确定')
	return True

def main():
	G.scaling = 1 
	config_location = None
	if len(sys.argv) > 1:
		if sys.argv[1] == '--list_themes':
			sg.preview_all_look_and_feel_themes()
			return
		if sys.argv[1] == '--config':
			if len(sys.argv) < 3:
				win_popup_button('没有提供带有 `--config` 参数的配置件文.\n请检查启动参数!', '确定')
				return
			else:
				config_location = sys.argv[2]
	setcmd()
	if not loadconfig(config_location):
		return False
	sg.theme(G.theme)
	loggedin = False
	while True:
		if not loggedin:
			loggedin = loginwindow()
			if not loggedin:
				if G.user and G.token_name and G.token_value: 
					return 1
				break
			else:
				vmstat = showvms()
				if not vmstat:
					G.proxmox = None
					loggedin = False
					if G.user and G.token_name and G.token_value: 
						return 0
				else:
					return

if __name__ == '__main__':
	sys.exit(main())
