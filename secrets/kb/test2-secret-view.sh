kubectl  describe secret $(kubectl  get secret | grep test2-secret | awk '{print $1}')
