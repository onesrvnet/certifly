ALTER TABLE "trust_bundles" ADD COLUMN "traefik_enabled" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "trust_bundles" ADD COLUMN "traefik_client_auth" boolean DEFAULT true NOT NULL;--> statement-breakpoint
ALTER TABLE "trust_bundles" ADD COLUMN "traefik_client_auth_type" text DEFAULT 'RequireAndVerifyClientCert' NOT NULL;--> statement-breakpoint
ALTER TABLE "trust_bundles" ADD COLUMN "traefik_tls_option_name" text;--> statement-breakpoint
ALTER TABLE "trust_bundles" ADD COLUMN "traefik_servers_transport" boolean DEFAULT true NOT NULL;--> statement-breakpoint
ALTER TABLE "trust_bundles" ADD COLUMN "traefik_servers_transport_name" text;--> statement-breakpoint
ALTER TABLE "trust_bundles" ADD COLUMN "traefik_require_token" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "trust_bundles" ADD COLUMN "traefik_token_hash" text;