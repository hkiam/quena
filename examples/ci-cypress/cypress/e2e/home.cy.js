describe("home", () => {
  it("opens the commands overview", () => {
    cy.visit("/");
    cy.contains("Commands").click();
    cy.contains("Querying").should("be.visible");
  });
});
