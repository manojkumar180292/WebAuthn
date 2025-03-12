using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace WebAuthnDemo.Migrations
{
    /// <inheritdoc />
    public partial class AddBiometricColumnsToUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "HasRegisteredFaceId",
                table: "Users",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "HasRegisteredFingerprint",
                table: "Users",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "HasRegisteredFaceId",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "HasRegisteredFingerprint",
                table: "Users");
        }
    }
}
