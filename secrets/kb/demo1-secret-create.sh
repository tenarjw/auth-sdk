# UWAGA! Najpierw utwórz sekret test1-secret-create.sh
kubectl apply -f demo1s.yaml
# test
kubectl get pods -o wide
kubectl describe pod py3a