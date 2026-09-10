const AllocationsDAO = require("../data/allocations-dao").AllocationsDAO;
const {
    environmentalScripts
} = require("../../config/config");

function AllocationsHandler(db) {
    "use strict";

    const allocationsDAO = new AllocationsDAO(db);

    this.displayAllocations = (req, res, next) => {
        const userId = req.session && req.session.userId;
        if (!userId) return res.status(401).send("Authentication required");
        const {
            threshold
        } = req.query;

        if (threshold !== undefined && threshold !== '' &&
            (typeof threshold !== 'string' || !/^\d{1,2}(?:\.\d+)?$/.test(threshold) || Number(threshold) > 99)) {
            return res.status(400).send('Invalid allocation threshold');
        }
        allocationsDAO.getByUserIdAndThreshold(userId, threshold, (err, allocations) => {
            if (err) return next(err);
            return res.render("allocations", {
                userId,
                allocations,
                environmentalScripts
            });
        });
    };
}

module.exports = AllocationsHandler;
