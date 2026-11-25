CREATE TABLE "ssh_security_key_enrollments" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"cli_session_id" uuid NOT NULL,
	"challenge" "bytea" NOT NULL,
	"user_code" text NOT NULL,
	"machine_hostname" text NOT NULL,
	"machine_os" text NOT NULL,
	"status" "cli_login_status" DEFAULT 'pending' NOT NULL,
	"name" text,
	"public_key" text,
	"fingerprint" text,
	"application" text,
	"aaguid" text,
	"attestation_subject" text,
	"attested" boolean DEFAULT false NOT NULL,
	"submitted_at" timestamp with time zone,
	"ssh_security_key_id" uuid,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ssh_security_keys" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"name" text NOT NULL,
	"public_key" text NOT NULL,
	"fingerprint" text NOT NULL,
	"application" text NOT NULL,
	"aaguid" text,
	"attestation_subject" text,
	"attested" boolean DEFAULT false NOT NULL,
	"machine" text,
	"last_used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"revoked_by_user_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "ssh_security_key_enrollments" ADD CONSTRAINT "ssh_security_key_enrollments_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssh_security_key_enrollments" ADD CONSTRAINT "ssh_security_key_enrollments_cli_session_id_cli_sessions_id_fk" FOREIGN KEY ("cli_session_id") REFERENCES "public"."cli_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssh_security_key_enrollments" ADD CONSTRAINT "ssh_security_key_enrollments_ssh_security_key_id_ssh_security_keys_id_fk" FOREIGN KEY ("ssh_security_key_id") REFERENCES "public"."ssh_security_keys"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssh_security_keys" ADD CONSTRAINT "ssh_security_keys_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssh_security_keys" ADD CONSTRAINT "ssh_security_keys_revoked_by_user_id_users_id_fk" FOREIGN KEY ("revoked_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "ssh_security_key_enrollments_user_idx" ON "ssh_security_key_enrollments" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "ssh_security_key_enrollments_expires_idx" ON "ssh_security_key_enrollments" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "ssh_security_keys_fingerprint_idx" ON "ssh_security_keys" USING btree ("fingerprint");--> statement-breakpoint
CREATE INDEX "ssh_security_keys_user_idx" ON "ssh_security_keys" USING btree ("user_id","created_at");