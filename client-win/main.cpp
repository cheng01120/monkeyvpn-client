#include "wx/wx.h"
#include "wx/stdpaths.h"
#include "wx/file.h"
#include "wx/sizer.h"
#include "wx/statline.h"
#include "wx/richtooltip.h"
#include "wx/msw/registry.h"
#include "wx/taskbar.h"
#include "wx/aboutdlg.h"
#include "wx/fileconf.h"
#include "wx/utils.h"

#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>

#include <iostream>
#include <sstream>
#include <set>
#include <regex>

/* third party libraries */
#include <monkeyvpn/monkeyvpn.h>

#include "vl_packet.hpp"
#include "tap_device.hpp"


// The network thread communicates with the GUI by posting a wxTheadEvent with id = ID_THREAD to it.
// diffrent integers means diffrent types.
// the actual content is stored in string part of the event.
#define ID_THREAD_LOG                1  /* log */
#define ID_THREAD_CONNECTION_SUCCESS 2  /* notify the GUI the connection established successfullly */
#define ID_THREAD_CONNECTION_FAIL    3  /* connection failed. */
#define ID_THREAD_ERROR              4  /* error occured */
#define ID_THREAD_DOWNLOAD           5
#define ID_THREAD_UPLOAD             6
#define ID_THREAD_EXIT               7

enum {
	ID_TIMER = 10001,
	ID_THREAD,

	ID_SERVER_ADDR,
	ID_SERVER_PORT,
	ID_USERNAME,
	ID_PASSWORD,

	ID_ENABLE_LZF,
	ID_REMEMBER_ME,

	ID_SUBMIT,
	ID_RESET,
	ID_ABOUT,

	ID_SHOW_LOG,
	ID_EXIT_THREAD,

	ID_EXIT_packet,
};

/* ECDH curve */
#define uECC_CURVE uECC_secp256k1()

#define ec2str(ec)  ec.message().c_str()
#define CONFIG_DIR wxPathOnly(wxStandardPaths::Get().GetUserConfigDir())
#define vlTrimedVal(s) s->GetValue().Trim()
#define wx2str(s)  std::string(s.ToUTF8().data())

#define LOG_TRACE 0
#define LOG_INFO  1
#define LOG_ERROR 2

#define TRACE_LEVEL LOG_INFO

static unsigned char g_retry = 0; // num of retry when connection error.


using boost::asio::ip::tcp;
namespace ba = boost::asio;


// forward declaration of VLFrame
class VLFrame;
class VLTaskBarIcon;

// --------------------- VLThread ----------------------------------------------------
class VLThread : public wxThread
{
public:
	VLThread(VLFrame *);

protected:
	VLFrame *m_packet;

	unsigned char m_mac[6]; // mac address of the device.
	friend class VLSession;

private:
	virtual ExitCode Entry();
	virtual void     OnExit();
};

//--------------------- VLFrame -------------------------------------------------------
class VLFrame : public wxFrame
{
public:
	VLFrame(const wxString&);
	~VLFrame();

	void TerminateThread();

protected:
	wxCriticalSection m_critsec;
	std::string s_username, s_password, s_server, s_port;
	bool b_enable_lzf;

	friend class VLThread;
	friend class VLSession;

private:
	void OnShowLog(wxCommandEvent&);
	void OnSubmit(wxCommandEvent&);
	void OnReset(wxCommandEvent&);
	void OnAbout(wxCommandEvent&);
	void OnThreadEvent(wxThreadEvent&);
	void OnClose(wxCloseEvent&);
	void OnKeyDown(wxKeyEvent&);
	void OnUpdateUIRange(wxUpdateUIEvent& event);

	void CreateTaskBarIcon();
	void RemoveTaskBarIcon();

	wxTextCtrl *m_server, *m_port,  *m_username, *m_password;
	wxCheckBox *m_enable_lzf, *m_remember_me;

	void OnpacketExit(wxCommandEvent&);

	wxString Num2Str(uint64_t);

	wxLog      *m_oldLogTarget;
	wxTextCtrl *m_textLog;
	wxDialog   *m_logDialog;


	wxButton   *m_submit, *m_reset, *m_about;

	VLTaskBarIcon *m_taskBarIcon;

	VLThread *m_thread;
	bool m_thread_running;

	uint64_t m_upload, m_download; // bytes uploaded and downloaded.

	wxDECLARE_EVENT_TABLE();
};
//----------- VLSession class ----------------------------------------------------------
class VLSession
{
public:
	VLSession(VLThread *t, ba::io_service&, HANDLE);
	void Start();

private:
	void RecvServerPubKey();
	void SendClientPubKey();
	void ComputeSharedSecret();
	void SendID();
	void ReadAuthResult();
	void StartRead();
	void StartReadFromNetwork();
	void StartReadFromTap();
	void WriteToNetwork();
	void WriteToTap();

	/* type: ID_THREAD_UPLOAD or ID_THREAD_DOWNLOAD */
	void ShowBytesXferred(int type, int num_bytes);

	void PostEvent(int event_id, const wxString& msg);

	void Close();

	void TRACE(int priority, const char *format, ...);

	ba::windows::stream_handle m_dev;
	tcp::socket  m_network;
	VLFrame* m_packet;

	vl_packet packet_dev, packet_network;
	uint8_t client_pubkey[64], client_privkey[32];
	uint8_t server_pubkey[64], shared_secret[32];
	uint8_t aes_buf[2048], lzf_buf[2048];

	uint8_t m_authed;
	bool enable_lzf;

	VLThread *m_thread;
};

VLSession::VLSession(VLThread *t, ba::io_service& io_service, HANDLE h)
	: m_thread(t), m_dev(io_service, h), m_network(io_service)
{
	m_packet  = t->m_packet;
	m_authed = 0;
	enable_lzf = m_packet->b_enable_lzf;
}

void VLSession::TRACE(int priority, const char *format, ...) {
	if(priority < TRACE_LEVEL) return;

	wxThreadEvent event(wxEVT_THREAD, ID_THREAD);
	event.SetInt( ID_THREAD_LOG );

	char message[4096] = "";

	va_list args;
	va_start(args, format);
	vsnprintf(message, 4096 - 1, format, args);
	va_end(args);

	event.SetString(message);
	wxQueueEvent((wxFrame *)m_packet, event.Clone());

	if(priority == LOG_ERROR && !m_thread->TestDestroy()) {
		PostEvent(ID_THREAD_ERROR, message);
	}
}

void VLSession::PostEvent(int event_id, const wxString& msg) {
	wxThreadEvent event(wxEVT_THREAD, ID_THREAD);
	event.SetInt( event_id );
	event.SetString(msg);
	wxQueueEvent((wxFrame *)m_packet, event.Clone());
}

void VLSession::Start() {
	// generate client public and private key.
	if (!uECC_make_key(client_pubkey, client_privkey, uECC_CURVE)) {
		TRACE(LOG_ERROR, "Unable to make key!");
		return;
	}

	tcp::resolver resolver(m_network.get_io_service());
	boost::system::error_code ec;
	auto endpoint_iterator
		= resolver.resolve( tcp::resolver::query( m_packet->s_server, m_packet->s_port), ec);
	if(ec) {
		TRACE(LOG_ERROR, "Unable to resolve hostname");
		return;
	}

	ba::async_connect(m_network, endpoint_iterator,
		[this](boost::system::error_code ec, tcp::resolver::iterator) {
			if(ec) {
				TRACE(LOG_ERROR, "Error connect to remote: %s", ec2str(ec));
				Close();
				return;
			}

			TRACE(LOG_INFO, "Successfully connected to remote");
			RecvServerPubKey();
		});
}

void VLSession::RecvServerPubKey() {
	ba::async_read(m_network, ba::buffer(server_pubkey, 64),
		[this](boost::system::error_code ec, std::size_t)
		{
			if(ec) {
				TRACE(LOG_ERROR, "Error receiving server public key: %s", ec2str(ec));
				Close();
				return;
			}

			if(!uECC_valid_public_key(server_pubkey, uECC_CURVE)) {
				TRACE(LOG_ERROR, "Invalid public key received!");
				Close();
				return;
			}

			TRACE(LOG_INFO, "Successfully received server public key.");
			SendClientPubKey();
		});
}

void VLSession::SendClientPubKey() {
	ba::async_write(m_network, ba::buffer(client_pubkey, 64),
		[this](boost::system::error_code ec, std::size_t) {
			if(ec) {
				TRACE(LOG_ERROR, "Unable to send client public key: %s", ec2str(ec));
				Close();
				return;
			}

			// Compute the shared secret.
			ComputeSharedSecret();
		});
}

void VLSession::ComputeSharedSecret() {
	if(!uECC_shared_secret(server_pubkey, client_privkey, shared_secret, uECC_CURVE)) {
		TRACE(LOG_ERROR, "Unable to compute shared secret!");
		Close();
		return;
	}

	SendID();
}

/* send mac address, username, password to server */
void VLSession::SendID() {
	uint8_t buffer[64];
	int i, m, n;

	/* format of ID:
	 * 1 byte len(length of mac + user + "|" + pass),
	 * 1 byte flags,
	 * 6 byte mac,
	 * then user + "|" + pass */
	std::string user_and_pass;
	{
		wxCriticalSectionLocker enter(m_packet->m_critsec);
		user_and_pass =  m_packet->s_username + "|" + m_packet->s_password;
		m_packet->s_password = "";
	}

	if(user_and_pass.size() > 64 - XOR_KEYLEN - 2 - 6) {
		TRACE(LOG_ERROR, "Invalid username and password length!");
		Close();
		return;
	}

	uint8_t *pos = buffer + 2;
	memcpy(pos,  m_thread->m_mac, 6);
	memcpy(pos + 6,  user_and_pass.c_str(), user_and_pass.size());

	// xor encrypt
	uint8_t total_len = 6 + user_and_pass.size();
	for(m = 0; m < total_len; m++) {
		n = m % XOR_KEYLEN;
		pos[m] ^= shared_secret[n];
	}
	buffer[0] = total_len;
	buffer[1] = enable_lzf ? 1 : 0;

	ba::async_write(m_network, ba::buffer(buffer, total_len + 2),
		[this, &buffer](boost::system::error_code ec, std::size_t) {
			if(ec) {
				TRACE(LOG_ERROR, "Error sending identity: %s", ec2str(ec));
				Close();
				return;
			}

			//StartRead();
			ReadAuthResult();
		});
}

void VLSession::ReadAuthResult() {
	ba::async_read(m_network, ba::buffer(&m_authed, 1),
		[this](boost::system::error_code ec, std::size_t) {
			if(ec || !m_authed) {
				PostEvent(ID_THREAD_CONNECTION_FAIL, "Authentication failed.");
				Close();
				return;
			}

			PostEvent(ID_THREAD_CONNECTION_SUCCESS, "Successfully connected to server.");
			StartRead();
		});
}

void VLSession::StartRead() {
	StartReadFromNetwork();
	StartReadFromTap();
}

void VLSession::ShowBytesXferred(int type, int num_bytes) {
	wxThreadEvent event(wxEVT_THREAD, ID_THREAD);
	event.SetInt(type);
	event.SetString( wxString::Format("%d", num_bytes));
	wxQueueEvent( (wxFrame *)m_packet, event.Clone());
}

void VLSession::StartReadFromNetwork() {

	ba::async_read(m_network, ba::buffer(packet_network.data(), vl_packet::header_length),
		[this](boost::system::error_code ec, std::size_t len) {
			if(ec) {
				TRACE(LOG_ERROR, "Error read header from network: %s", ec2str(ec));
				Close();
				return;
			}

			// Read body.
			packet_network.decode_header();
			ba::async_read(m_network, ba::buffer(packet_network.body(), packet_network.body_length()),
				[this](boost::system::error_code ec, std::size_t bytes_read) {
					if(ec) {
						TRACE(LOG_ERROR, "Error read body from network: %s", ec2str(ec));
						Close();
						return;
					}
					TRACE(LOG_TRACE, "Read %d bytes of body data", bytes_read);
					ShowBytesXferred(ID_THREAD_DOWNLOAD, bytes_read + vl_packet::header_length);

					if( bytes_read % XOR_KEYLEN ) {
						TRACE(LOG_ERROR, "Invalid block size: %d", bytes_read);
						Close();
						return;
					}

					unsigned packet_len  = bytes_read;

					// decrypt the packet.
					uint8_t *pos   = (uint8_t *)packet_network.body();
					int m, n;
					for(m = 0; m < packet_len; m++) {
						n = m % XOR_KEYLEN;
						pos[m] ^= shared_secret[n];
					}

					// lzf uncomperss.
					if(enable_lzf) {
						packet_len
							= lzf_decompress(pos, packet_len, lzf_buf, 2048);
						memcpy(pos, lzf_buf, packet_len);
					}
					else {
						packet_len = packet_len;
					}

					packet_network.body_length(packet_len);
					packet_network.encode_header();

					WriteToTap();
				}); // read body.
		}); // read header.
}

void VLSession::WriteToTap() {
	ba::async_write(m_dev, ba::buffer(packet_network.body(), packet_network.body_length()),
		[this](boost::system::error_code ec, std::size_t len) {
			if(ec) {
				TRACE(LOG_ERROR, "Error write to device: %s", ec2str(ec));
				Close();
				return;
			}

			TRACE(LOG_TRACE, "Write %d bytes to device", len);

			if(!m_thread->TestDestroy())
				StartReadFromNetwork();
			else
				Close();
		}); // write to TAP.
}

void VLSession::StartReadFromTap() {
	m_dev.async_read_some( ba::buffer(packet_dev.body(), vl_packet::max_body_length),
		[this](boost::system::error_code ec, std::size_t bytes_read) {
			if(ec) {
				// Do NOT log tap read error.
				//TRACE(LOG_ERROR, "Error read from device: %s", ec2str(ec));
				Close();
				return;
			}

			// compress the packet.
			unsigned packet_len = bytes_read;

			if(enable_lzf) {
				packet_len = lzf_compress(packet_dev.body(), bytes_read, lzf_buf, 2048);
			}

			int m, n;
			for(m = 0; m < packet_len; m++) {
				n = m % XOR_KEYLEN;
				lzf_buf[m] ^= shared_secret[n];
			}
			memcpy(packet_dev.body(), lzf_buf, packet_len);
			packet_dev.body_length(packet_len);
			packet_dev.encode_header();

			WriteToNetwork();
		});
}

void VLSession::WriteToNetwork() {
	// send data to network.
	ba::async_write(m_network, ba::buffer(packet_dev.data(), packet_dev.length()),
		[this](boost::system::error_code ec, std::size_t bytes_written) {
			if(ec) {
				TRACE(LOG_ERROR, "Error write to network: %s", ec2str(ec));
				Close();
				return;
			}
			TRACE(LOG_TRACE, "Write %d bytes to network", bytes_written);
			ShowBytesXferred(ID_THREAD_UPLOAD, bytes_written);

			if(!m_thread->TestDestroy())
				StartReadFromTap();
			else
				Close();
		});
}

void VLSession::Close() {
	m_network.close();
	m_dev.close();
}

//--------------------- VLApp -----------------------------------------------
class VLApp : public wxApp {
public:
	virtual bool OnInit();
};

//--------------------- VLTaskBarIcon --------------------------------------
class VLTaskBarIcon : public wxTaskBarIcon
{
public:
#if defined(__WXOSX__) && wxOSX_USE_COCOA
	VLTaskBarIcon(wxTaskBarIconType iconType = wxTBI_DEFAULT_TYPE) : wxTaskBarIcon(iconType)
#else
	VLTaskBarIcon(VLFrame *packet)
#endif
	{ m_packet = packet; }

	virtual wxMenu *CreatePopupMenu();

private:
	void OnAbout(wxCommandEvent&);
	void OnShowLog(wxCommandEvent&);
	void OnQuitThread(wxCommandEvent&);

	VLFrame *m_packet;
	wxDECLARE_EVENT_TABLE();
};


IMPLEMENT_APP(VLApp)

bool VLApp::OnInit() {
	if( !wxApp::OnInit())
		return false;

	VLFrame *packet = new VLFrame("VirtualLAN");
	packet->Center();
	packet->Show(true);

	SetTopWindow(packet);
	return true;
}


//---------------------------------------------------------------------------------------
wxBEGIN_EVENT_TABLE( VLTaskBarIcon, wxTaskBarIcon)
	EVT_TOOL(ID_ABOUT, VLTaskBarIcon::OnAbout)
	EVT_TOOL(ID_EXIT_THREAD,  VLTaskBarIcon::OnQuitThread)
	EVT_TOOL(ID_SHOW_LOG, VLTaskBarIcon::OnShowLog)
wxEND_EVENT_TABLE()
wxMenu *VLTaskBarIcon::CreatePopupMenu()
{
	wxMenu *menu = new wxMenu;
	menu->Append(ID_ABOUT, _("&About"));
	menu->Append(ID_SHOW_LOG, _("&Show log"));

#ifdef __WXOSX__
	if( OSXIsStatusItem() )
#endif
	{
		menu->AppendSeparator();
		menu->Append(ID_EXIT_THREAD,  _("&Quit"));
	}

	return menu;
}

void VLTaskBarIcon::OnAbout(wxCommandEvent& WXUNUSED(event))
{
	wxCommandEvent event(wxEVT_BUTTON, ID_ABOUT);
	wxPostEvent(m_packet, event);
}

void VLTaskBarIcon::OnShowLog(wxCommandEvent& WXUNUSED(event))
{
	wxCommandEvent event(wxEVT_MENU, ID_SHOW_LOG);
	wxPostEvent(m_packet, event);
}

void VLTaskBarIcon::OnQuitThread(wxCommandEvent& WXUNUSED(event))
{
	m_packet->TerminateThread();
}

//--------------------------------------------------------------------------------------
BEGIN_EVENT_TABLE(VLFrame, wxFrame)
	EVT_MENU(ID_SHOW_LOG, OnShowLog)

	EVT_BUTTON(ID_SUBMIT,  OnSubmit)
	EVT_BUTTON(ID_RESET, OnReset)
	EVT_BUTTON(ID_ABOUT, OnAbout)
	EVT_CLOSE( OnClose)

	EVT_UPDATE_UI_RANGE(ID_SERVER_ADDR, ID_ABOUT, OnUpdateUIRange)

	EVT_THREAD(ID_THREAD, OnThreadEvent)
	EVT_MENU(ID_EXIT_packet, OnpacketExit)
END_EVENT_TABLE()
VLFrame::VLFrame(const wxString& title)
	: wxFrame(NULL, wxID_ANY, title, wxDefaultPosition, wxDefaultSize,
			wxDEFAULT_FRAME_STYLE ^ wxRESIZE_BORDER)
{
	SetIcon(wxICON(flying));

	m_taskBarIcon = NULL;
	wxMenu *fileMenu = new wxMenu;
	fileMenu->Append(ID_SHOW_LOG, "Show log");
	fileMenu->Append(ID_EXIT_packet, "E&xit\tAlt-X",  "Quit this application");

	wxMenuBar *menuBar = new wxMenuBar();
	menuBar->Append(fileMenu, "&File");
	SetMenuBar(menuBar);

	wxSizer *topsizer = new wxBoxSizer(wxVERTICAL);

	wxPanel *p = new wxPanel(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxWANTS_CHARS);
	p->Bind(wxEVT_CHAR_HOOK, &VLFrame::OnKeyDown, this);
	wxFlexGridSizer *gridsizer = new wxFlexGridSizer(2, wxSize(5, 5));
	gridsizer->Add(new wxStaticText(p, wxID_ANY, _("Server:")));
	m_server = new wxTextCtrl(p, ID_SERVER_ADDR, _("srdc.virtuallan.net"),
			wxDefaultPosition, wxSize(300, wxDefaultSize.y));
	m_port   = new wxTextCtrl(p, ID_SERVER_PORT, _("443"),
			wxDefaultPosition, wxSize(60, wxDefaultSize.y));

	wxBoxSizer *serverSizer = new wxBoxSizer(wxHORIZONTAL);
	serverSizer->Add(m_server);
	serverSizer->Add(new wxStaticText(p, wxID_ANY, _(" : ")));
	serverSizer->Add(m_port);

	gridsizer->Add(serverSizer);

	gridsizer->Add(new wxStaticText(p, wxID_ANY, _("Username:")));
	m_username = new wxTextCtrl(p, ID_USERNAME, "", wxDefaultPosition, wxSize(260, wxDefaultSize.y));
	gridsizer->Add(m_username);

	gridsizer->Add(new wxStaticText(p, wxID_ANY, _("Password:")));
	m_password = new wxTextCtrl(p, ID_PASSWORD, "", wxDefaultPosition, wxSize(260, wxDefaultSize.y),
			wxTE_PASSWORD);
	gridsizer->Add(m_password);

	// enable LZF
	//wxBoxSizer* sz_check1  = new wxBoxSizer(wxHORIZONTAL);
	m_enable_lzf = new wxCheckBox(p, ID_ENABLE_LZF, _("Enable Compression"));
	gridsizer->Add(m_enable_lzf);
	m_remember_me = new wxCheckBox(p, ID_REMEMBER_ME, _("Remember me"));
	gridsizer->Add(m_remember_me);

	topsizer->Add(gridsizer, 0, wxALL, 10);

	/* static line */
	topsizer->Add(
		new wxStaticLine( p,
			wxID_ANY, wxDefaultPosition, wxSize(3, 3), wxHORIZONTAL), 0, wxEXPAND | wxALL, 10);

	/* button */
	wxBoxSizer *button_box = new wxBoxSizer(wxHORIZONTAL);
	m_submit = new wxButton(p, ID_SUBMIT, _("Connect"));
	button_box->Add(m_submit, 0, wxALL, 10);
	m_reset  = new wxButton(p, ID_RESET, _("Reset"));
	button_box->Add(m_reset, 0, wxALL, 10);
	m_about  = new wxButton(p, ID_ABOUT, _("About"));
	button_box->Add(m_about, 0, wxALL, 10);

	topsizer->Add(button_box);

	p->SetSizer(topsizer);
	//topsizer->SetSizeHints(this);
	topsizer->Fit(this);
	m_username->SetFocus();

	/* read saved configuration back */
	wxString path( CONFIG_DIR + "/.vl_config.ini");
	if(wxFileExists(path)) {
		wxString val;

		wxFileConfig conf("", "", path);
		conf.Read("ServerAddr", &val);
		if( !val.IsEmpty()) m_server->SetValue(val);
		conf.Read("ServerPort", &val);
		if(!val.IsEmpty()) m_port->SetValue(val);
		conf.Read("Username", &val);
		if(!val.IsEmpty()) m_username->SetValue(val);
		conf.Read("Password", &val);
		if(!val.IsEmpty()) m_password->SetValue( val);
		conf.Read("EnableCompression", &val);
		if(!val.IsEmpty()) m_enable_lzf->SetValue( wxAtoi(val) ? true : false );
		conf.Read("RememberMe", &val);
		if(!val.IsEmpty()) m_remember_me->SetValue( wxAtoi(val) ? true : false );
	}

	m_logDialog = new wxDialog(this, wxID_ANY, "Log",
			wxDefaultPosition, wxSize(600, 400), wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER);
	wxSizer *sz = new wxBoxSizer(wxHORIZONTAL);
	m_textLog = new wxTextCtrl(m_logDialog, wxID_ANY, "",
			wxDefaultPosition, wxDefaultSize, wxTE_READONLY | wxTE_MULTILINE);
	sz->Add(m_textLog, 1, wxEXPAND);
	m_logDialog->SetSizer(sz);

	m_oldLogTarget = wxLog::SetActiveTarget(new wxLogTextCtrl(m_textLog));

	m_thread_running = false;
	m_download = m_upload = 0;

	// Auto fire the connection process when username, password and server is not empty.
	/*
	if(m_server->GetValue().Length()
			&& m_port->GetValue().Length()
			&& m_username->GetValue().Length()
			&& m_password->GetValue().Length())
	{
		//wxMessageBox(_("Ready to connect."));
		wxCommandEvent event(wxEVT_BUTTON, ID_SUBMIT);
		wxPostEvent(this, event);
	}
	*/
}

VLFrame::~VLFrame() {
	delete wxLog::SetActiveTarget(m_oldLogTarget);
}

void VLFrame::OnpacketExit(wxCommandEvent& event) {
	Close(true);
}

void VLFrame::OnThreadEvent(wxThreadEvent& event)
{
	int id = event.GetInt();
	wxRichToolTip *tip = NULL;
	wxFileConfig *conf = NULL;
	wxString path(CONFIG_DIR + "/.vl_config.ini");
	//std::string s_password;

	switch(id) {
		case ID_THREAD_CONNECTION_SUCCESS:
			// Minimize to task bar.
			g_retry = 0;
			Show(false);
			CreateTaskBarIcon();
			m_taskBarIcon->ShowBalloon("VirtualLAN", _("Running"), 3000, wxICON_INFORMATION);
			wxLogMessage("Connected.");

			// save or delete the config file.
			if(m_remember_me->GetValue()) {
				conf = new wxFileConfig("", "", path);
				conf->Write("ServerAddr", m_server->GetValue());
				conf->Write("ServerPort", m_port->GetValue());
				conf->Write("Username", m_username->GetValue());
				conf->Write("Password", m_password->GetValue());
				conf->Write("EnableCompression", m_enable_lzf->GetValue() ? "1" : "0");
				conf->Write("RememberMe", m_remember_me->GetValue() ? "1" : "0");
				conf->Flush();
				delete conf;
			}
			else {
				// delete the config file.
				wxRemoveFile(path);
			}
			break;

		case ID_THREAD_CONNECTION_FAIL:
			tip = new wxRichToolTip("Error",
					_("Authentication failed! please check your username and password."));
			tip->SetIcon(wxICON_ERROR);
			tip->ShowFor(m_password);
			delete tip;
			g_retry += 1;
			if(g_retry < 5) {
				wxCommandEvent event(wxEVT_BUTTON, ID_SUBMIT);
				wxPostEvent(this, event);
			}
			break;

		case ID_THREAD_LOG:
			wxLogMessage( event.GetString() );
			break;

		case ID_THREAD_ERROR:
			//if(m_taskBarIcon) RemoveTaskBarIcon();
			//if(!IsShown()) Show(true);
			//wxMessageBox(event.GetString(), "Error", wxICON_ERROR);
			//tip = new wxRichToolTip("Error", event.GetString());
			//tip->SetIcon(wxICON_ERROR);
			//tip->ShowFor(m_taskBarIcon);
			//delete tip;
			m_taskBarIcon->ShowBalloon(_("Network error!"), event.GetString(), 10000, wxICON_ERROR);

			g_retry += 1;
			if(g_retry < 5) {
				// reconnect.
				wxCommandEvent event(wxEVT_BUTTON, ID_SUBMIT);
				wxPostEvent(this, event);
			}
			else {
				if(m_taskBarIcon) RemoveTaskBarIcon();
				if(!IsShown()) Show(true);
				wxMessageBox(_("Unable to reconnect to server, aborting."), "Error", wxICON_ERROR);
			}

			break;

		case ID_THREAD_UPLOAD:
			m_upload += wxAtoi(event.GetString());
			m_taskBarIcon->SetIcon(wxICON(flying),
					wxString::Format("Up: %s \nDown: %s", Num2Str(m_upload), Num2Str(m_download)));
			break;

		case ID_THREAD_DOWNLOAD:
			m_download += wxAtoi(event.GetString());
			m_taskBarIcon->SetIcon(wxICON(flying),
					wxString::Format("Up: %s \nDown: %s", Num2Str(m_upload), Num2Str(m_download)));
			break;

		case ID_THREAD_EXIT:
			m_thread_running = false;
			RemoveTaskBarIcon();
			if(!IsShown()) Close(true);
			break;

		default:
			break;
	}
}

wxString VLFrame::Num2Str(uint64_t num) {
	char buf[256];
	int len;

	len = snprintf(buf, 255, "%llu", num);
	std::string s(buf, buf + len);
	len -= 3;
	while(len > 0) {
		s.insert(len, ",");
		len -= 3;
	}
	return wxString::Format("%s", s.c_str());
}


void VLFrame::OnAbout(wxCommandEvent& WXUNUSED(evt)) {
	wxAboutDialogInfo info;

	info.SetIcon(wxICON(flying));
	info.SetName( _("VirtualLAN") );
	info.SetVersion( _("ver 1.0") );
	info.SetDescription(_("Connect geographically distributed systems to a single LAN."));
	info.SetCopyright(_("(C) 2016  VirtualLAN co, Ltd"));
	info.AddDeveloper(_("VirtualLAN Develper team, <dev@virtuallan.net>"));
	info.SetWebSite(_("http://virtuallan.net"));

	wxAboutBox(info, this);
}

void VLFrame::OnReset(wxCommandEvent& WXUNUSED(event)) {
	m_password->SetValue("");
}

void VLFrame::OnSubmit(wxCommandEvent& WXUNUSED(event)) {
	// server address.
	s_username = wx2str(vlTrimedVal(m_username));
	s_password = wx2str(vlTrimedVal(m_password));
	s_server   = wx2str(vlTrimedVal(m_server));
	s_port     = wx2str(vlTrimedVal(m_port));
	b_enable_lzf = m_enable_lzf->GetValue();

	//if(!std::regex_match(s_server,
	//std::regex("^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$"))) {
	//std::regex("^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})$"))) {
	if(s_server.empty()) {
		wxRichToolTip tip( "Error", _("Invalid server address specified."));
		tip.SetIcon(wxICON_WARNING);
		tip.ShowFor(m_server);
		return;
	}

	// port.
	int port = atoi( s_port.c_str());
	if( port >= 65535 || port <= 0 ) {
		wxRichToolTip tip( "Error", _("Invalid server port!"));
		tip.SetIcon(wxICON_WARNING);
		tip.ShowFor(m_port);
		return;
	}

	// username.
	if(!std::regex_match(s_username, std::regex("^[a-zA-Z0-9_-]{3,16}$"))) {
		wxRichToolTip tip( "Error", _("Invalid username!"));
		tip.SetIcon(wxICON_WARNING);
		tip.ShowFor(m_username);
		return;
	}

	// password.
	if(!std::regex_match(s_password, std::regex("^[a-zA-Z0-9_-]{6,18}$"))) {
		wxRichToolTip tip( "Error", _("Invalid password!"));
		tip.SetIcon(wxICON_WARNING);
		tip.ShowFor(m_password);
		return;
	}

	// Disallow input when launching thread.
	m_thread_running = true;
	m_thread = new VLThread(this);
	if(m_thread->Create() != wxTHREAD_NO_ERROR) {
		wxMessageBox( _("Unable to launch thread!"), "Error", wxICON_ERROR);
		m_thread_running = false;
		return;
	}
	m_thread->Run();
}

void VLFrame::OnShowLog(wxCommandEvent& WXUNUSED(event)) {
	if( m_logDialog->IsShown())
		return;
	m_logDialog->Show(true);
}

void VLFrame::TerminateThread() {
	// Terminate the thread.
	{
		wxCriticalSectionLocker enter(m_critsec);
		if(m_thread) {
			if(m_thread->Delete() != wxTHREAD_NO_ERROR) {
				wxMessageBox( _("Unable to stop thread!"), "Error",  wxICON_ERROR);
			}
		}
	}
}

void VLFrame::OnClose(wxCloseEvent& event) {
	if(m_thread_running) {
		event.Veto();
	}
	else {
		Destroy();
	}
}

void VLFrame::OnKeyDown(wxKeyEvent& event) {
	if(event.GetKeyCode() == WXK_RETURN) {
		wxCommandEvent event(wxEVT_BUTTON, ID_SUBMIT);
		wxPostEvent(this, event);
	}
	else {
		event.Skip();
	}
}

void VLFrame::OnUpdateUIRange(wxUpdateUIEvent& event)
{
	event.Enable(!m_thread_running);
}

void VLFrame::CreateTaskBarIcon()
{
	if( m_taskBarIcon) return;

	/* Show the task bar icon. */
	m_taskBarIcon = new VLTaskBarIcon(this);
	m_taskBarIcon->SetIcon(wxICON(flying), "VirtualLAN" );
#if defined(__WXOSX__) && wxOSX_USE_COCOA
	m_dockIcon = new VLTaskBarIcon(wxTBI_DOCK);
	m_dockIcon->SetIcon(wxICON(flying));
#endif
}

void VLFrame::RemoveTaskBarIcon()
{
	if(m_taskBarIcon)
	{
		delete m_taskBarIcon;
		m_taskBarIcon = NULL;
	}
#if defined(__WXCOCOA__)
	if(m_dockIcon)
	{
		delete m_dockIcon;
		m_dockIcon = NULL;
	}
#endif
}

VLThread::VLThread(VLFrame *packet) : wxThread()
{
	m_packet = packet;
}

void VLThread::OnExit() {
	wxThreadEvent event(wxEVT_THREAD, ID_THREAD);
	event.SetInt(ID_THREAD_EXIT);
	event.SetString("Thread terminates.");
	wxQueueEvent(m_packet, event.Clone());
}

wxThread::ExitCode VLThread::Entry() {
	try {
		HANDLE hdl = OpenDevice();
		if(hdl == INVALID_HANDLE_VALUE) {
			wxThreadEvent event(wxEVT_THREAD, ID_THREAD);
			event.SetInt(ID_THREAD_ERROR);
			event.SetString( _("Unable to open TAP device!"));
			wxQueueEvent(m_packet, event.Clone());
			return NULL;
		}
		GetMacAddress(hdl, m_mac);
		EnableDevice(hdl);

		ba::io_service io_service;
		VLSession s(this, io_service, hdl);
		s.Start();
		io_service.run();
	}
	catch(std::exception& e) {
		wxMessageBox(e.what(), "Error", wxICON_ERROR);
	}

	return NULL;
}
