CREATE TYPE "public"."acme_account_status" AS ENUM('valid', 'deactivated', 'revoked');--> statement-breakpoint
CREATE TYPE "public"."acme_authorization_status" AS ENUM('pending', 'valid', 'invalid', 'deactivated', 'expired', 'revoked');--> statement-breakpoint
CREATE TYPE "public"."acme_challenge_status" AS ENUM('pending', 'processing', 'valid', 'invalid');--> statement-breakpoint
CREATE TYPE "public"."acme_challenge_type" AS ENUM('http-01', 'tls-alpn-01');--> statement-breakpoint
CREATE TYPE "public"."acme_order_status" AS ENUM('pending', 'ready', 'processing', 'valid', 'invalid');--> statement-breakpoint
CREATE TABLE "acme_accounts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"template_id" uuid NOT NULL,
	"eab_key_id" uuid NOT NULL,
	"jwk_thumbprint" text NOT NULL,
	"jwk" jsonb NOT NULL,
	"contact" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"status" "acme_account_status" DEFAULT 'valid' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "acme_authorizations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"order_id" uuid NOT NULL,
	"identifier" jsonb NOT NULL,
	"status" "acme_authorization_status" DEFAULT 'pending' NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "acme_challenges" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"authorization_id" uuid NOT NULL,
	"type" "acme_challenge_type" NOT NULL,
	"token" text NOT NULL,
	"status" "acme_challenge_status" DEFAULT 'pending' NOT NULL,
	"validated_at" timestamp with time zone,
	"error" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "acme_eab_keys" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"template_id" uuid NOT NULL,
	"name" text NOT NULL,
	"kid" text NOT NULL,
	"hmac_key_encrypted" text NOT NULL,
	"created_by_user_id" uuid,
	"last_used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "acme_eab_keys_kid_unique" UNIQUE("kid")
);
--> statement-breakpoint
CREATE TABLE "acme_nonces" (
	"nonce" text PRIMARY KEY NOT NULL,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "acme_orders" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"account_id" uuid NOT NULL,
	"status" "acme_order_status" DEFAULT 'pending' NOT NULL,
	"identifiers" jsonb NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"certificate_id" uuid,
	"error" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "est_credentials" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"template_id" uuid NOT NULL,
	"name" text NOT NULL,
	"username" text NOT NULL,
	"password_hash" text NOT NULL,
	"created_by_user_id" uuid,
	"last_used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "est_credentials_username_unique" UNIQUE("username")
);
--> statement-breakpoint
ALTER TABLE "acme_accounts" ADD CONSTRAINT "acme_accounts_template_id_templates_id_fk" FOREIGN KEY ("template_id") REFERENCES "public"."templates"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "acme_accounts" ADD CONSTRAINT "acme_accounts_eab_key_id_acme_eab_keys_id_fk" FOREIGN KEY ("eab_key_id") REFERENCES "public"."acme_eab_keys"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "acme_authorizations" ADD CONSTRAINT "acme_authorizations_order_id_acme_orders_id_fk" FOREIGN KEY ("order_id") REFERENCES "public"."acme_orders"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "acme_challenges" ADD CONSTRAINT "acme_challenges_authorization_id_acme_authorizations_id_fk" FOREIGN KEY ("authorization_id") REFERENCES "public"."acme_authorizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "acme_eab_keys" ADD CONSTRAINT "acme_eab_keys_template_id_templates_id_fk" FOREIGN KEY ("template_id") REFERENCES "public"."templates"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "acme_eab_keys" ADD CONSTRAINT "acme_eab_keys_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "acme_orders" ADD CONSTRAINT "acme_orders_account_id_acme_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."acme_accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "acme_orders" ADD CONSTRAINT "acme_orders_certificate_id_certificates_id_fk" FOREIGN KEY ("certificate_id") REFERENCES "public"."certificates"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "est_credentials" ADD CONSTRAINT "est_credentials_template_id_templates_id_fk" FOREIGN KEY ("template_id") REFERENCES "public"."templates"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "est_credentials" ADD CONSTRAINT "est_credentials_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "acme_accounts_template_idx" ON "acme_accounts" USING btree ("template_id");--> statement-breakpoint
CREATE INDEX "acme_accounts_thumbprint_idx" ON "acme_accounts" USING btree ("template_id","jwk_thumbprint");--> statement-breakpoint
CREATE INDEX "acme_authorizations_order_idx" ON "acme_authorizations" USING btree ("order_id");--> statement-breakpoint
CREATE INDEX "acme_challenges_authorization_idx" ON "acme_challenges" USING btree ("authorization_id");--> statement-breakpoint
CREATE INDEX "acme_eab_keys_template_idx" ON "acme_eab_keys" USING btree ("template_id");--> statement-breakpoint
CREATE INDEX "acme_nonces_expires_idx" ON "acme_nonces" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "acme_orders_account_idx" ON "acme_orders" USING btree ("account_id");--> statement-breakpoint
CREATE INDEX "est_credentials_template_idx" ON "est_credentials" USING btree ("template_id");