import React from "react";
import ReactDOM from "react-dom";
// import FWUpd from "fwupd";
// import SPKCal from "spkcal";

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

class SPKCal extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      spk_latency: 0,
      prog_st: 0,
      reasonLatency: "",
      reasonAuto: "",
    };
  }

  spkcalLatencyClicked(ev) {
    console.log(ev);
    this.setState((state, props) => ({
      reasonLatency: ev.target.id
    }));
  }

  spkcalAutoClicked(ev) {
    console.log(ev);
    this.setState((state, props) => ({
      reasonAuto: ev.target.id
    }));
  }

  render() {
    return (<div>
      <h2>Speaker Latency</h2>
      <p>
        This section setup the latency between audio signal output from hardware terminal and audable from speaker<br />
      </p>
      <p>
        <label>Set latency in milliseconds:<br />
          <input type="number" name="spkcal_latency_text" id="spkcal_latency_text" value={this.state.spk_latency} />
        </label>
        <button type="button" id="set" onClick={this.spkcalLatencyClicked.bind(this)}>Set</button>
        <button type="button" id="get" onClick={this.spkcalLatencyClicked.bind(this)}>Get</button>
        <em>{this.state.reasonLatency}</em>
        <br />
      </p>
      <p>
        The auto calibration process will take about 30 seconds, take device closer to speaker before start.<br />
        <button type="button" id="auto" onClick={this.spkcalAutoClicked.bind(this)}>Start Auto Calibration</button>
        <em>{this.state.reasonAuto}</em>
      </p>
    </div>);
  }
};


ReactDOM.render(
  <div>
    <FWUpd />
    <hr />
    <SPKCal />
  </div>,
  document.getElementById("root")
);
