kubectl  describe secret $(kubectl  get secret | grep test-secret1 | awk '{print $1}')
