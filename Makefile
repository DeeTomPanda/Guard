build:
	cd dashboard && flutter build web --base-href=/app/ 
	cargo build --release 