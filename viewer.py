# Nessus results viewing tools
#
# Developed by Felix Ingram, f.ingram@gmail.com, @lllamaboy
# http://www.github.com/nccgroup/nessusviewer
#
# Released under AGPL. See LICENSE for more information

if __name__ == '__main__':
    import sys
    try:
        import wx
    except ImportError:
        print("""\
You need to install WXPython to use the viewer

http://wxpython.org/download.php
""")
        sys.exit()
    from controller import ViewerController
    app = wx.App(0)
    ViewerController()
    app.MainLoop()
