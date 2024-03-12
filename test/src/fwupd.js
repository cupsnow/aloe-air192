import React from "react";
import ReactDOM from "react-dom";

export default
  class FWUpd extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      ota_file_uri: "http://10.0.1.103:3000/media/ota.tar.gz",
      ota_enforce: false,
      prog_st: 0
    };
  }

  render() {
    return (<div>
      <h2>Firmware Update</h2>
      <form action="/cgi-bin/admin_fwupd.cgi">
        <p>
          <label>OTA File URI:<br />
            <input type="text" name="ota_file_uri" value={this.state.ota_file_uri} />
          </label> <br />
          <label>Enforce even completed
            <input type="checkbox" name="ota_enforce" defaultChecked={this.state.ota_enforce} />
          </label>
        </p>
        <p>
          <label>Comment:<br />
            <input type="text" name="comment" value="comment" />
          </label><br />
        </p>
        <input type="submit" value="Submit" />
      </form>
    </div>);
  }
};

// ReactDOM.render(
//   <FWUpd />,
//   document.getElementById("root")
// );
