from mininet.topo import Topo

class Grid(Topo):
  def __init__(self,**opts):
    Topo.__init__(self, **opts)
    srcHost1 = self.addHost('h1')
    srcHost2 = self.addHost('h2')
    dstHost = self.addHost('h3')

    n = 2
    self.switch = {}
    for s in range(n*n):
      self.switch[s] = self.addSwitch('s%s' %(s+1))
    for index in range(n*n):
      if index == (n*n-1):
        continue
      if (index % n) == (n-1):
        self.addDownLink(index, n)
      elif index >= (n*(n-1)):
        self.addRightLink(index, n)
      else:
        self.addRightLink(index, n)
        self.addDownLink(index, n)
    self.addLink(self.switch[0],srcHost1, )
    self.addLink(self.switch[0],srcHost2, )
    self.addLink(self.switch[n*n-1],dstHost, )

  def addDownLink(self, index, n):
    self.addLink(self.switch[index], self.switch[index+n])

  def addRightLink(self, index, n):
    self.addLink(self.switch[index], self.switch[index+1])
topos = { 'Grid2': ( lambda: Grid() ) }
