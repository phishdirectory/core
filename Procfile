web: bin/rails server -p $PORT -e production
worker: RAILS_MAX_THREADS=10 bundle exec rake solid_queue:start
