CREATE TYPE "public"."actor_type" AS ENUM('user', 'api_key', 'acme', 'est', 'system');--> statement-breakpoint
CREATE TYPE "public"."alert_channel_kind" AS ENUM('email', 'webhook');--> statement-breakpoint
CREATE TYPE "public"."alert_delivery_status" AS ENUM('pending', 'sent', 'retrying', 'failed');--> statement-breakpoint
CREATE TYPE "public"."alert_event" AS ENUM('expiring', 'issued', 'revoked', 'ca_expiring', 'crl_failed');--> statement-breakpoint
CREATE TYPE "public"."ca_signing" AS ENUM('self_signed', 'internal', 'external');--> statement-breakpoint
CREATE TYPE "public"."ca_status" AS ENUM('pending_certificate', 'active', 'disabled', 'expired');--> statement-breakpoint
CREATE TYPE "public"."certificate_source" AS ENUM('ui', 'api', 'acme', 'est', 'import');--> statement-breakpoint
CREATE TYPE "public"."certificate_status" AS ENUM('active', 'revoked', 'expired', 'superseded');--> statement-breakpoint
CREATE TYPE "public"."key_source" AS ENUM('local');--> statement-breakpoint
CREATE TYPE "public"."tag_color" AS ENUM('gray', 'blue', 'teal', 'green', 'yellow', 'orange', 'pink', 'violet');--> statement-breakpoint
CREATE TYPE "public"."template_status" AS ENUM('active', 'archived');--> statement-breakpoint
CREATE TYPE "public"."user_role" AS ENUM('admin', 'operator', 'viewer');--> statement-breakpoint
CREATE TABLE "alert_channels" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"kind" "alert_channel_kind" NOT NULL,
	"config" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "alert_deliveries" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"rule_id" uuid,
	"channel_id" uuid,
	"event" "alert_event",
	"test" boolean DEFAULT false NOT NULL,
	"subject_type" text,
	"subject_id" uuid,
	"dedupe_key" text NOT NULL,
	"status" "alert_delivery_status" DEFAULT 'pending' NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"last_error" text,
	"payload" jsonb NOT NULL,
	"last_attempt_at" timestamp with time zone,
	"sent_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "alert_deliveries_dedupe_key_unique" UNIQUE("dedupe_key")
);
--> statement-breakpoint
CREATE TABLE "alert_rules" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"event" "alert_event" NOT NULL,
	"filter" jsonb NOT NULL,
	"days_before" integer[] DEFAULT '{}' NOT NULL,
	"channel_ids" uuid[] NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "api_keys" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"name" text NOT NULL,
	"secret_hash" text NOT NULL,
	"last4" text NOT NULL,
	"expires_at" timestamp with time zone,
	"last_used_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "api_keys_secret_hash_unique" UNIQUE("secret_hash")
);
--> statement-breakpoint
CREATE TABLE "ca_certificates" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"ca_id" uuid NOT NULL,
	"key_id" uuid NOT NULL,
	"issuer_ca_id" uuid,
	"issuer_key_id" uuid,
	"version" integer NOT NULL,
	"certificate_der" "bytea" NOT NULL,
	"chain_pem" text NOT NULL,
	"serial" text NOT NULL,
	"issuer_dn" text NOT NULL,
	"not_before" timestamp with time zone NOT NULL,
	"not_after" timestamp with time zone NOT NULL,
	"fingerprint_sha256" text NOT NULL,
	"revoked_at" timestamp with time zone,
	"revocation_reason" integer,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ca_csrs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"ca_id" uuid NOT NULL,
	"key_id" uuid NOT NULL,
	"csr_pem" text NOT NULL,
	"requested_path_length" integer,
	"created_by_id" uuid,
	"consumed_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ca_keys" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"ca_id" uuid NOT NULL,
	"key_source" "key_source" DEFAULT 'local' NOT NULL,
	"algorithm" text NOT NULL,
	"public_key_spki" "bytea" NOT NULL,
	"alg" text NOT NULL,
	"kek_id" text NOT NULL,
	"wrapped_dek" "bytea" NOT NULL,
	"dek_iv" "bytea" NOT NULL,
	"dek_tag" "bytea" NOT NULL,
	"ciphertext" "bytea" NOT NULL,
	"iv" "bytea" NOT NULL,
	"tag" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "certificate_authorities" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"slug" text NOT NULL,
	"name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"signing" "ca_signing" NOT NULL,
	"parent_ca_id" uuid,
	"status" "ca_status" NOT NULL,
	"subject_dn" text NOT NULL,
	"key_algorithm" text NOT NULL,
	"max_path_length" integer,
	"name_constraints" jsonb,
	"active_cert_id" uuid,
	"active_key_id" uuid,
	"crl_validity_hours" integer NOT NULL,
	"crl_overlap_hours" integer NOT NULL,
	"not_before" timestamp with time zone,
	"not_after" timestamp with time zone,
	"disabled_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"revocation_reason" integer,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "certificate_authorities_slug_unique" UNIQUE("slug"),
	CONSTRAINT "certificate_authorities_parent_check" CHECK (("certificate_authorities"."signing" = 'internal') = ("certificate_authorities"."parent_ca_id" is not null)),
	CONSTRAINT "certificate_authorities_crl_hours_check" CHECK ("certificate_authorities"."crl_overlap_hours" >= 0 and "certificate_authorities"."crl_overlap_hours" < "certificate_authorities"."crl_validity_hours")
);
--> statement-breakpoint
CREATE TABLE "certificate_tags" (
	"certificate_id" uuid NOT NULL,
	"tag_id" uuid NOT NULL,
	CONSTRAINT "certificate_tags_certificate_id_tag_id_pk" PRIMARY KEY("certificate_id","tag_id")
);
--> statement-breakpoint
CREATE TABLE "certificates" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"ca_id" uuid,
	"ca_cert_id" uuid,
	"template_id" uuid,
	"source" "certificate_source" NOT NULL,
	"status" "certificate_status" DEFAULT 'active' NOT NULL,
	"serial" text NOT NULL,
	"subject_dn" text NOT NULL,
	"issuer_dn" text NOT NULL,
	"common_name" text,
	"sans" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"key_algorithm" text NOT NULL,
	"key_usages" text[] NOT NULL,
	"extended_key_usages" text[] NOT NULL,
	"not_before" timestamp with time zone NOT NULL,
	"not_after" timestamp with time zone NOT NULL,
	"fingerprint_sha256" text NOT NULL,
	"certificate_der" "bytea" NOT NULL,
	"csr_pem" text,
	"key_generated" boolean DEFAULT false NOT NULL,
	"revoked_at" timestamp with time zone,
	"revocation_reason" integer,
	"superseded_by_id" uuid,
	"requested_by_user_id" uuid,
	"requested_by_api_key_id" uuid,
	"labels" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"notes" text DEFAULT '' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "certificates_import_check" CHECK (("certificates"."source" = 'import') = ("certificates"."ca_id" is null)),
	CONSTRAINT "certificates_ca_cert_check" CHECK (("certificates"."ca_id" is null) = ("certificates"."ca_cert_id" is null))
);
--> statement-breakpoint
CREATE TABLE "crls" (
	"ca_id" uuid NOT NULL,
	"key_id" uuid NOT NULL,
	"crl_number" bigint NOT NULL,
	"this_update" timestamp with time zone NOT NULL,
	"next_update" timestamp with time zone NOT NULL,
	"crl_der" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "crls_ca_id_key_id_pk" PRIMARY KEY("ca_id","key_id")
);
--> statement-breakpoint
CREATE TABLE "email_tokens" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" text NOT NULL,
	"token_hash" text NOT NULL,
	"code_hash" text NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"meta" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "email_tokens_token_hash_unique" UNIQUE("token_hash")
);
--> statement-breakpoint
CREATE TABLE "events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"actor_type" "actor_type" NOT NULL,
	"actor_id" uuid,
	"name" text NOT NULL,
	"subject_type" text,
	"subject_id" uuid,
	"data" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"ip" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "instance_settings" (
	"key" text PRIMARY KEY NOT NULL,
	"value" jsonb NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "invites" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" text NOT NULL,
	"role" "user_role" DEFAULT 'viewer' NOT NULL,
	"invited_by_id" uuid,
	"token_hash" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"accepted_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "invites_token_hash_unique" UNIQUE("token_hash")
);
--> statement-breakpoint
CREATE TABLE "passkeys" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"credential_id" text NOT NULL,
	"public_key" "bytea" NOT NULL,
	"counter" bigint DEFAULT 0 NOT NULL,
	"transports" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"name" text NOT NULL,
	"last_used_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "passkeys_credential_id_unique" UNIQUE("credential_id")
);
--> statement-breakpoint
CREATE TABLE "rate_limits" (
	"key" text NOT NULL,
	"window_start" timestamp with time zone NOT NULL,
	"count" integer DEFAULT 0 NOT NULL,
	CONSTRAINT "rate_limits_key_window_start_pk" PRIMARY KEY("key","window_start")
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"user_agent" text,
	"ip_address" text,
	"reauth_at" timestamp with time zone,
	"last_active_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "tags" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"color" "tag_color" DEFAULT 'gray' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "template_tags" (
	"template_id" uuid NOT NULL,
	"tag_id" uuid NOT NULL,
	CONSTRAINT "template_tags_template_id_tag_id_pk" PRIMARY KEY("template_id","tag_id")
);
--> statement-breakpoint
CREATE TABLE "templates" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"slug" text NOT NULL,
	"name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"ca_id" uuid NOT NULL,
	"status" "template_status" DEFAULT 'active' NOT NULL,
	"allowed_san_types" text[] NOT NULL,
	"allowed_dns" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"allowed_ips" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"allow_wildcards" boolean DEFAULT false NOT NULL,
	"require_san" boolean DEFAULT true NOT NULL,
	"require_common_name" boolean DEFAULT false NOT NULL,
	"subject_defaults" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"allowed_subject_fields" text[] NOT NULL,
	"key_algorithms" text[] NOT NULL,
	"max_ttl_seconds" integer NOT NULL,
	"default_ttl_seconds" integer NOT NULL,
	"key_usages" text[] NOT NULL,
	"extended_key_usages" text[] NOT NULL,
	"allow_server_keygen" boolean DEFAULT false NOT NULL,
	"allow_acme" boolean DEFAULT false NOT NULL,
	"allow_est" boolean DEFAULT false NOT NULL,
	"renew_before_days" integer NOT NULL,
	"archived_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "templates_slug_unique" UNIQUE("slug"),
	CONSTRAINT "templates_ttl_check" CHECK ("templates"."default_ttl_seconds" > 0 and "templates"."default_ttl_seconds" <= "templates"."max_ttl_seconds")
);
--> statement-breakpoint
CREATE TABLE "trust_bundle_cas" (
	"bundle_id" uuid NOT NULL,
	"ca_id" uuid NOT NULL,
	"position" integer NOT NULL,
	CONSTRAINT "trust_bundle_cas_bundle_id_ca_id_pk" PRIMARY KEY("bundle_id","ca_id")
);
--> statement-breakpoint
CREATE TABLE "trust_bundles" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"slug" text NOT NULL,
	"name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"include_chain" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "trust_bundles_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "user_identities" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"provider" text NOT NULL,
	"provider_user_id" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" text NOT NULL,
	"name" text NOT NULL,
	"role" "user_role" DEFAULT 'viewer' NOT NULL,
	"preferences" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"last_active_at" timestamp with time zone,
	"last_signed_in_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "alert_deliveries" ADD CONSTRAINT "alert_deliveries_rule_id_alert_rules_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."alert_rules"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_deliveries" ADD CONSTRAINT "alert_deliveries_channel_id_alert_channels_id_fk" FOREIGN KEY ("channel_id") REFERENCES "public"."alert_channels"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ca_certificates" ADD CONSTRAINT "ca_certificates_ca_id_certificate_authorities_id_fk" FOREIGN KEY ("ca_id") REFERENCES "public"."certificate_authorities"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ca_certificates" ADD CONSTRAINT "ca_certificates_key_id_ca_keys_id_fk" FOREIGN KEY ("key_id") REFERENCES "public"."ca_keys"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ca_certificates" ADD CONSTRAINT "ca_certificates_issuer_ca_id_certificate_authorities_id_fk" FOREIGN KEY ("issuer_ca_id") REFERENCES "public"."certificate_authorities"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ca_certificates" ADD CONSTRAINT "ca_certificates_issuer_key_id_ca_keys_id_fk" FOREIGN KEY ("issuer_key_id") REFERENCES "public"."ca_keys"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ca_csrs" ADD CONSTRAINT "ca_csrs_ca_id_certificate_authorities_id_fk" FOREIGN KEY ("ca_id") REFERENCES "public"."certificate_authorities"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ca_csrs" ADD CONSTRAINT "ca_csrs_key_id_ca_keys_id_fk" FOREIGN KEY ("key_id") REFERENCES "public"."ca_keys"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ca_csrs" ADD CONSTRAINT "ca_csrs_created_by_id_users_id_fk" FOREIGN KEY ("created_by_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ca_keys" ADD CONSTRAINT "ca_keys_ca_id_certificate_authorities_id_fk" FOREIGN KEY ("ca_id") REFERENCES "public"."certificate_authorities"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certificate_authorities" ADD CONSTRAINT "certificate_authorities_parent_ca_id_certificate_authorities_id_fk" FOREIGN KEY ("parent_ca_id") REFERENCES "public"."certificate_authorities"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certificate_authorities" ADD CONSTRAINT "certificate_authorities_active_cert_id_ca_certificates_id_fk" FOREIGN KEY ("active_cert_id") REFERENCES "public"."ca_certificates"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certificate_authorities" ADD CONSTRAINT "certificate_authorities_active_key_id_ca_keys_id_fk" FOREIGN KEY ("active_key_id") REFERENCES "public"."ca_keys"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certificate_tags" ADD CONSTRAINT "certificate_tags_certificate_id_certificates_id_fk" FOREIGN KEY ("certificate_id") REFERENCES "public"."certificates"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certificate_tags" ADD CONSTRAINT "certificate_tags_tag_id_tags_id_fk" FOREIGN KEY ("tag_id") REFERENCES "public"."tags"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certificates" ADD CONSTRAINT "certificates_ca_id_certificate_authorities_id_fk" FOREIGN KEY ("ca_id") REFERENCES "public"."certificate_authorities"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certificates" ADD CONSTRAINT "certificates_ca_cert_id_ca_certificates_id_fk" FOREIGN KEY ("ca_cert_id") REFERENCES "public"."ca_certificates"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certificates" ADD CONSTRAINT "certificates_template_id_templates_id_fk" FOREIGN KEY ("template_id") REFERENCES "public"."templates"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certificates" ADD CONSTRAINT "certificates_superseded_by_id_certificates_id_fk" FOREIGN KEY ("superseded_by_id") REFERENCES "public"."certificates"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certificates" ADD CONSTRAINT "certificates_requested_by_user_id_users_id_fk" FOREIGN KEY ("requested_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certificates" ADD CONSTRAINT "certificates_requested_by_api_key_id_api_keys_id_fk" FOREIGN KEY ("requested_by_api_key_id") REFERENCES "public"."api_keys"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "crls" ADD CONSTRAINT "crls_ca_id_certificate_authorities_id_fk" FOREIGN KEY ("ca_id") REFERENCES "public"."certificate_authorities"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "crls" ADD CONSTRAINT "crls_key_id_ca_keys_id_fk" FOREIGN KEY ("key_id") REFERENCES "public"."ca_keys"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "invites" ADD CONSTRAINT "invites_invited_by_id_users_id_fk" FOREIGN KEY ("invited_by_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "passkeys" ADD CONSTRAINT "passkeys_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "template_tags" ADD CONSTRAINT "template_tags_template_id_templates_id_fk" FOREIGN KEY ("template_id") REFERENCES "public"."templates"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "template_tags" ADD CONSTRAINT "template_tags_tag_id_tags_id_fk" FOREIGN KEY ("tag_id") REFERENCES "public"."tags"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "templates" ADD CONSTRAINT "templates_ca_id_certificate_authorities_id_fk" FOREIGN KEY ("ca_id") REFERENCES "public"."certificate_authorities"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "trust_bundle_cas" ADD CONSTRAINT "trust_bundle_cas_bundle_id_trust_bundles_id_fk" FOREIGN KEY ("bundle_id") REFERENCES "public"."trust_bundles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "trust_bundle_cas" ADD CONSTRAINT "trust_bundle_cas_ca_id_certificate_authorities_id_fk" FOREIGN KEY ("ca_id") REFERENCES "public"."certificate_authorities"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_identities" ADD CONSTRAINT "user_identities_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "alert_deliveries_created_idx" ON "alert_deliveries" USING btree ("created_at","id");--> statement-breakpoint
CREATE INDEX "alert_deliveries_rule_idx" ON "alert_deliveries" USING btree ("rule_id");--> statement-breakpoint
CREATE INDEX "alert_deliveries_channel_idx" ON "alert_deliveries" USING btree ("channel_id");--> statement-breakpoint
CREATE INDEX "api_keys_user_idx" ON "api_keys" USING btree ("user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "ca_certificates_version_idx" ON "ca_certificates" USING btree ("ca_id","version");--> statement-breakpoint
CREATE UNIQUE INDEX "ca_certificates_issuer_serial_idx" ON "ca_certificates" USING btree ("issuer_ca_id","serial");--> statement-breakpoint
CREATE UNIQUE INDEX "ca_certificates_fingerprint_idx" ON "ca_certificates" USING btree ("ca_id","fingerprint_sha256");--> statement-breakpoint
CREATE INDEX "ca_csrs_ca_created_idx" ON "ca_csrs" USING btree ("ca_id","created_at");--> statement-breakpoint
CREATE INDEX "ca_keys_ca_idx" ON "ca_keys" USING btree ("ca_id");--> statement-breakpoint
CREATE INDEX "ca_keys_kek_idx" ON "ca_keys" USING btree ("kek_id");--> statement-breakpoint
CREATE INDEX "certificate_authorities_parent_idx" ON "certificate_authorities" USING btree ("parent_ca_id");--> statement-breakpoint
CREATE INDEX "certificate_tags_tag_idx" ON "certificate_tags" USING btree ("tag_id");--> statement-breakpoint
CREATE UNIQUE INDEX "certificates_ca_serial_idx" ON "certificates" USING btree ("ca_id","serial");--> statement-breakpoint
CREATE UNIQUE INDEX "certificates_fingerprint_idx" ON "certificates" USING btree ("fingerprint_sha256");--> statement-breakpoint
CREATE INDEX "certificates_created_idx" ON "certificates" USING btree ("created_at","id");--> statement-breakpoint
CREATE INDEX "certificates_not_after_idx" ON "certificates" USING btree ("not_after","id");--> statement-breakpoint
CREATE INDEX "certificates_template_idx" ON "certificates" USING btree ("template_id");--> statement-breakpoint
CREATE INDEX "certificates_status_idx" ON "certificates" USING btree ("status");--> statement-breakpoint
CREATE INDEX "certificates_superseded_by_idx" ON "certificates" USING btree ("superseded_by_id");--> statement-breakpoint
CREATE INDEX "certificates_ca_cert_idx" ON "certificates" USING btree ("ca_cert_id");--> statement-breakpoint
CREATE INDEX "crls_next_update_idx" ON "crls" USING btree ("next_update");--> statement-breakpoint
CREATE INDEX "email_tokens_email_idx" ON "email_tokens" USING btree ("email","created_at");--> statement-breakpoint
CREATE INDEX "events_created_idx" ON "events" USING btree ("created_at","id");--> statement-breakpoint
CREATE INDEX "events_actor_created_idx" ON "events" USING btree ("actor_id","created_at");--> statement-breakpoint
CREATE INDEX "events_name_created_idx" ON "events" USING btree ("name","created_at");--> statement-breakpoint
CREATE INDEX "events_subject_created_idx" ON "events" USING btree ("subject_type","subject_id","created_at");--> statement-breakpoint
CREATE INDEX "invites_email_idx" ON "invites" USING btree ("email");--> statement-breakpoint
CREATE UNIQUE INDEX "invites_pending_email_idx" ON "invites" USING btree ("email") WHERE "invites"."accepted_at" is null;--> statement-breakpoint
CREATE INDEX "passkeys_user_idx" ON "passkeys" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "sessions_user_idx" ON "sessions" USING btree ("user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "tags_name_lower_idx" ON "tags" USING btree (lower("name"));--> statement-breakpoint
CREATE INDEX "template_tags_tag_idx" ON "template_tags" USING btree ("tag_id");--> statement-breakpoint
CREATE INDEX "templates_ca_idx" ON "templates" USING btree ("ca_id");--> statement-breakpoint
CREATE INDEX "trust_bundle_cas_ca_idx" ON "trust_bundle_cas" USING btree ("ca_id");--> statement-breakpoint
CREATE UNIQUE INDEX "user_identities_provider_subject_idx" ON "user_identities" USING btree ("provider","provider_user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "users_email_lower_idx" ON "users" USING btree (lower("email"));