# Nessus results viewing tools
#
# Developed by Felix Ingram, f.ingram@gmail.com, @lllamaboy
# http://www.github.com/nccgroup/nessusviewer
#
# Released under AGPL. See LICENSE for more information

if __name__ == '__main__':
    from controller import ViewerController
    from view import ViewerView
    from interactor import ViewerInteractor
    app = ViewerController(ViewerView(), ViewerInteractor())
