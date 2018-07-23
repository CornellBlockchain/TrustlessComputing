
contract('mainContract', function(accounts) {
  it("should assert true", function(done) {
    var mainContract = artifacts.require("mainContract.sol");
    var main_contract = mainContract.deployed();
    assert.isTrue(true);
    done();
  });
});
